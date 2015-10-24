require 'active_merchant/billing/gateways/migs/migs_codes'

require 'digest/md5' # Used in add_secure_hash
require 'nokogiri'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class MigsGateway < Gateway
      include MigsCodes

      API_VERSION = 1
      PAYMENT_ID_PARAM_NAME = "paymentId"
      SET_COOKIE_PARAM_NAME = "set-cookie"
      DEFAULT_GATEWAY_HOST = 'https://migs.mastercard.com.au'

      class_attribute :server_hosted_url, :merchant_hosted_url

      self.server_hosted_url = "#{DEFAULT_GATEWAY_HOST}/vpcpay"
      self.merchant_hosted_url = "#{DEFAULT_GATEWAY_HOST}/vpcdps"

      self.live_url = self.server_hosted_url

      attr_accessor :gateway_host, :offsite_payment_url

      # MiGS is supported throughout Asia Pacific, Middle East and Africa
      # MiGS is used in Australia (AU) by ANZ (eGate), CBA (CommWeb) and more
      # Source of Country List: http://www.scribd.com/doc/17811923
      self.supported_countries = %w(AU AE BD BN EG HK ID IN JO KW LB LK MU MV MY NZ OM PH QA SA SG TT VN)

      # The card types supported by the payment gateway
      self.supported_cardtypes = [:visa, :master, :american_express, :diners_club, :jcb]

      self.money_format = :cents

      # The homepage URL of the gateway
      self.homepage_url = 'http://mastercard.com/mastercardsps'

      # The name of the gateway
      self.display_name = 'MasterCard Internet Gateway Service (MiGS)'

      # Creates a new MigsGateway
      # The advanced_login/advanced_password fields are needed for
      # advanced methods such as the capture, refund and status methods
      #
      # ==== Options
      #
      # * <tt>:login</tt> -- The MiGS Merchant ID (REQUIRED)
      # * <tt>:password</tt> -- The MiGS Access Code (REQUIRED)
      # * <tt>:secure_hash</tt> -- The MiGS Secure Hash
      # (Required for Server Hosted payments)
      # * <tt>:advanced_login</tt> -- The MiGS AMA User
      # * <tt>:advanced_password</tt> -- The MiGS AMA User's password
      def initialize(options = {})
        requires!(options, :login, :password)
        super
      end

      # ==== Options
      #
      # * <tt>:order_id</tt> -- A reference for tracking the order (REQUIRED)
      # * <tt>:unique_id</tt> -- A unique id for this request (Max 40 chars).
      # If not supplied one will be generated.
      def purchase(money, creditcard, options = {})
        requires!(options, :order_id)

        post = {}

        add_amount(post, money, options)
        add_invoice(post, options)
        add_creditcard(post, creditcard)
        add_standard_parameters('pay', post, options[:unique_id])

        commit(post)
      end

      # MiGS works by merchants being either purchase only or authorize/capture
      # So authorize is the same as purchase when in authorize mode
      alias_method :authorize, :purchase

      # ==== Options
      #
      # * <tt>:unique_id</tt> -- A unique id for this request (Max 40 chars).
      # If not supplied one will be generated.
      def capture(money, authorization, options = {})
        requires!(@options, :advanced_login, :advanced_password)

        post = options.merge(:TransNo => authorization)

        add_amount(post, money, options)
        add_advanced_user(post)
        add_standard_parameters('capture', post, options[:unique_id])

        commit(post)
      end

      # ==== Options
      #
      # * <tt>:unique_id</tt> -- A unique id for this request (Max 40 chars).
      # If not supplied one will be generated.
      def refund(money, authorization, options = {})
        requires!(@options, :advanced_login, :advanced_password)

        post = options.merge(:TransNo => authorization)

        add_amount(post, money, options)
        add_advanced_user(post)
        add_standard_parameters('refund', post, options[:unique_id])

        commit(post)
      end

      def credit(money, authorization, options = {})
        ActiveMerchant.deprecated CREDIT_DEPRECATION_MESSAGE
        refund(money, authorization, options)
      end

      # Checks the status of a previous transaction
      # This can be useful when a response is not received due to network issues
      #
      # ==== Parameters
      #
      # * <tt>unique_id</tt> -- Unique id of transaction to find.
      #   This is the value of the option supplied in other methods or
      #   if not supplied is returned with key :MerchTxnRef
      def status(unique_id)
        requires!(@options, :advanced_login, :advanced_password)

        post = {}
        add_advanced_user(post)
        add_standard_parameters('queryDR', post, unique_id)

        commit(post)
      end

      # Generates a URL to redirect user to MiGS to process payment
      # Once user is finished MiGS will redirect back to specified URL
      # With a response hash which can be turned into a Response object
      # with purchase_offsite_response
      #
      # ==== Options
      #
      # * <tt>:order_id</tt> -- A reference for tracking the order (REQUIRED)
      # * <tt>:locale</tt> -- Change the language of the redirected page
      #   Values are 2 digit locale, e.g. en, es
      # * <tt>:return_url</tt> -- the URL to return to once the payment is complete
      # * <tt>:card_type</tt> -- Providing this skips the card type step.
      #   Values are ActiveMerchant formats: e.g. master, visa, american_express, diners_club
      # * <tt>:unique_id</tt> -- Unique id of transaction to find.
      #   If not supplied one will be generated.
      def purchase_offsite_url(money, options = {})
        requires!(options, :order_id, :return_url)
        requires!(@options, :secure_hash)

        post = {}

        add_amount(post, money, options)
        add_invoice(post, options)
        add_creditcard_type(post, options[:card_type]) if options[:card_type]

        post.merge!(
          :Locale => options[:locale] || 'en',
          :ReturnURL => options[:return_url]
        )

        add_standard_parameters('pay', post, options[:unique_id])

        add_secure_hash(post)

        (options[:url] || self.server_hosted_url) + '?' + post_data(post)
      end

      # Parses a response from purchase_offsite_url once user is redirected back
      #
      # ==== Parameters
      #
      # * <tt>data</tt> -- All params when offsite payment returns
      # e.g. returns to http://company.com/return?a=1&b=2, then input "a=1&b=2"
      def purchase_offsite_response(data)
        requires!(@options, :secure_hash)

        response_hash = parse(data)

        expected_secure_hash = calculate_secure_hash(response_hash.reject{|k, v| k == :SecureHash}, @options[:secure_hash])
        unless response_hash[:SecureHash] == expected_secure_hash
          raise SecurityError, "Secure Hash mismatch, response may be tampered with"
        end

        response_object(response_hash)
      end

      def test?
        @options[:login].start_with?('TEST')
      end

      def purchase_offsite(money, creditcard, options = {})
        requires!(options, :card_type)
        card_type = (options[:card_type_permission] == false) && options.delete(:card_type)

        offsite_url = purchase_offsite_url(money, {:url => offsite_server_hosted_url}.merge(options))
        p offsite_url
        offsite_url_response = ssl_head(offsite_url)

        payment_url = get_redirect_url(offsite_url_response)

        # set the payment id and headers from the response
        offsite_payment_id(payment_url)
        offsite_headers(offsite_url_response)

        # hit the payment url (select card type or payment form)
        p offsite_ssl_head(payment_url)["location"]
        navigate_to_payment_url_without_card_type_permission(card_type) if card_type

#        payment_response = offsite_ssl_post(
#          offsite_payment_url,
#          post_data(offsite_payment_request_params(creditcard), :prefix => false)
#        )

        p offsite_payment_url
        p offsite_headers
        p post_data(offsite_payment_request_params(creditcard), :prefix => false)

        #parse_offsite_payment_response(payment_response)

      end

      def gateway_host
        @gateway_host || DEFAULT_GATEWAY_HOST
      end

      private

      def parse_offsite_payment_response(response)
        File.write("foo.html", response)
        html = Nokogiri::HTML(response)
        form = html.at_xpath(".//form[@name='PAReq']")
        form_action = form["action"]
        pa_req_input =  form.at_xpath(".//input[@name='PaReq']")
        pa_req_value = pa_req_input["value"]
        term_url_input = form.at_xpath(".//input[@name='TermUrl']")
        term_url_value = term_url_input["value"]
        md_input = form.at_xpath(".//input[@name='MD']")
        md_input_value = md_input["value"]

        p form_action
      end

      def navigate_to_payment_url_without_card_type_permission(card_type)
        # hit card type URL
        choose_card_response = offsite_ssl_head(
          build_get_url(offsite_server_hosted_url, offsite_card_type_request_params(card_type))
        )

        # hit the payment form url
        offsite_ssl_head(get_redirect_url(choose_card_response))
      end

      def offsite_server_hosted_url
        migs_url("vpcpay") || server_hosted_url
      end

      def offsite_payment_url
        migs_url("ssl")
      end

      def migs_url(path)
        "#{gateway_host}/#{path}"
      end

      def offsite_payment_request_params(creditcard)
        # order of params is important here
        params = {}
        offsite_add_payment_id_params(params)
        params.merge(
          "cardno" => creditcard.number,
          "cardexpirymonth" => creditcard.month.to_s.rjust(2, '0'),
          "cardexpiryyear" => Date.new(creditcard.year.to_i).strftime("%y"),
          "cardsecurecode" => creditcard.verification_value
        )
      end

      def offsite_ssl_post(url, params)
        ssl_post(url, params, offsite_headers)
      end

      def offsite_ssl_head(url)
        ssl_head(url, offsite_headers)
      end

      def offsite_headers(response = nil)
        @offsite_headers ||= offsite_cookies(response)
      end

      def get_redirect_url(response)
        response["location"]
      end

      def offsite_card_type_request_params(card_type)
        params = {}
        add_creditcard_type(params, card_type)
        offsite_add_payment_id_params(params)
        params
      end

      def offsite_add_payment_id_params(params)
        params[PAYMENT_ID_PARAM_NAME] = offsite_payment_id
      end

      def offsite_cookies(response)
        {
          "Cookie" => response.get_fields(
            SET_COOKIE_PARAM_NAME
          ).map { |cookie| cookie.split("; ")[0] }.join("; ")
        }
      end

      def offsite_payment_id(url = nil)
        @offsite_payment_id ||= parse_url_params(url)[PAYMENT_ID_PARAM_NAME]
      end

      def parse_url_params(url)
        Hash[CGI::parse(URI.parse(url).query).map { |k, v| [k, v[0]] }]
      end

      def build_get_url(url, params)
        uri = URI.parse(url)
        uri.query = post_data(params, :prefix => false)
        uri.to_s
      end

      def add_amount(post, money, options)
        post[:Amount] = amount(money)
        post[:Currency] = options[:currency] if options[:currency]
      end

      def add_advanced_user(post)
        post[:User] = @options[:advanced_login]
        post[:Password] = @options[:advanced_password]
      end

      def add_invoice(post, options)
        post[:OrderInfo] = options[:order_id]
      end

      def add_creditcard(post, creditcard)
        post[:CardNum] = creditcard.number
        post[:CardSecurityCode] = creditcard.verification_value if creditcard.verification_value?
        post[:CardExp] = format(creditcard.year, :two_digits) + format(creditcard.month, :two_digits)
      end

      def add_creditcard_type(post, card_type)
        post[:Gateway]  = 'ssl'
        post[:card] = CARD_TYPES.detect{|ct| ct.am_code == card_type}.migs_long_code
      end

      def parse(body)
        params = CGI::parse(body)
        hash = {}
        params.each do |key, value|
          hash[key.gsub('vpc_', '').to_sym] = value[0]
        end
        hash
      end

      def commit(post)
        data = ssl_post self.merchant_hosted_url, post_data(post)
        response_hash = parse(data)
        response_object(response_hash)
      end

      def response_object(response)
        avs_response_code = response[:AVSResultCode]
        avs_response_code = 'S' if avs_response_code == "Unsupported"

        cvv_result_code = response[:CSCResultCode]
        cvv_result_code = 'P' if cvv_result_code == "Unsupported"

        Response.new(success?(response), response[:Message], response,
          :test => test?,
          :authorization => response[:TransactionNo],
          :fraud_review => fraud_review?(response),
          :avs_result => { :code => avs_response_code },
          :cvv_result => cvv_result_code
        )
      end

      def success?(response)
        response[:TxnResponseCode] == '0'
      end

      def fraud_review?(response)
        ISSUER_RESPONSE_CODES[response[:AcqResponseCode]] == 'Suspected Fraud'
      end

      def add_standard_parameters(action, post, unique_id = nil)
        post.merge!(
          :Version     => API_VERSION,
          :Merchant    => @options[:login],
          :AccessCode  => @options[:password],
          :Command     => action,
          :MerchTxnRef => unique_id || generate_unique_id.slice(0, 40)
        )
      end

      def post_data(post, options = {})
        post.collect do |key, value|
          prefixed_key = [(options[:prefix] == false ? nil : 'vpc'), key].compact.join("_")
          "#{prefixed_key}=#{CGI.escape(value.to_s)}"
        end.join("&")
      end

      def add_secure_hash(post)
        post[:SecureHash] = calculate_secure_hash(post, @options[:secure_hash])
      end

      def calculate_secure_hash(post, secure_hash)
        sorted_values = post.sort_by(&:to_s).map(&:last)
        input = secure_hash + sorted_values.join
        Digest::MD5.hexdigest(input).upcase
      end
    end
  end
end
