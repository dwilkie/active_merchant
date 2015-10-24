require 'test_helper'
require 'net/http'

class RemoteMigsTest < Test::Unit::TestCase
  include ActiveMerchant::NetworkConnectionRetries
  include ActiveMerchant::PostsData

  def setup
    @gateway = MigsGateway.new(fixtures(:migs_purchase))
    @capture_gateway = MigsGateway.new(fixtures(:migs_capture))

    @amount = 100
    @declined_amount = 105
    @visa   = credit_card('4005550000000001', :month => 5, :year => 2017, :brand => 'visa')
    @master = credit_card('5123456789012346', :month => 5, :year => 2017, :brand => 'master')
    @amex   = credit_card('371449635311004',  :month => 5, :year => 2017, :brand => 'american_express')
    @diners = credit_card('30123456789019',   :month => 5, :year => 2017, :brand => 'diners_club')
    @credit_card = @visa

    @options = {
      :order_id => '1'
    }

    @purchase_offsite_url_options = {
      :order_id => '1',
      :unique_id  => 9,
      :return_url => 'http://localhost:8080/payments/return'
    }
  end

  def test_purchase_offsite_url
    choice_url = @gateway.purchase_offsite_url(@amount, @purchase_offsite_url_options)
    assert_response_match /Pay securely by clicking on the card logo below/, choice_url
  end

  def test_purchase_offsite_url_with_card_type
    # This fails then redirects with error:
    # vpc_Message:E5000: No bank links are configured for merchant [TESTANZTEST2]

    responses = {
      'visa'             => /You have chosen .*VISA.*/,
      'master'           => /You have chosen .*MasterCard.*/,
      'diners_club'      => /You have chosen .*Diners Club.*/,
      'american_express' => /You have chosen .*American Express.*/
    }

    responses.each_pair do |card_type, response_text|
      url = @capture_gateway.purchase_offsite_url(@amount, @purchase_offsite_url_options.merge(:card_type => card_type))
      assert_response_match response_text, url
    end
  end

  #TEST=./test/remote/gateways/remote_migs_test.rb TESTOPTS="--name=test_purchase_offsite" bundle exec rake test:remote

  def test_purchase_offsite
    purchase_offsite_options = @purchase_offsite_url_options.merge(
      :card_type => "visa",
    )

    assert response = @gateway.purchase_offsite(@amount, @credit_card, @options.merge(purchase_offsite_options))
  end

  def test_purchase_offsite_select_card
    gateway = MigsGateway.new(fixtures(:migs_purchase_select_card))
    gateway.gateway_host = 'https://migs-mtf.mastercard.com.au'

    purchase_offsite_options = @purchase_offsite_url_options.merge(
      :card_type => "visa", :card_type_permission => false
    )

    assert response = gateway.purchase_offsite(@amount, @credit_card, @options.merge(purchase_offsite_options))
  end

  def test_successful_purchase
    assert response = @gateway.purchase(@amount, @credit_card, @options)
    assert_success response
    assert_equal 'Approved', response.message
  end

  def test_unsuccessful_purchase
    assert response = @gateway.purchase(@declined_amount, @credit_card, @options)
    assert_failure response
    assert_equal 'Declined', response.message
  end

  def test_authorize_and_capture
    assert auth = @capture_gateway.authorize(@amount, @credit_card, @options)
    assert_success auth
    assert_equal 'Approved', auth.message
    assert capture = @capture_gateway.capture(@amount, auth.authorization, @options)
    assert_success capture
  end

  def test_failed_authorize
    assert response = @capture_gateway.authorize(@declined_amount, @credit_card, @options)
    assert_failure response
    assert_equal 'Declined', response.message
  end

  def test_refund
    assert payment_response = @gateway.purchase(@amount, @credit_card, @options)
    assert_success payment_response
    assert response = @gateway.refund(@amount, payment_response.authorization, @options)
    assert_success response
    assert_equal 'Approved', response.message
  end

  def test_status
    purchase_response = @gateway.purchase(@declined_amount, @credit_card, @options)
    assert response = @gateway.status(purchase_response.params['MerchTxnRef'])
    assert_equal 'Y', response.params['DRExists']
    assert_equal 'N', response.params['FoundMultipleDRs']
  end

  def test_invalid_login
    gateway = MigsGateway.new(:login => '', :password => '')
    assert response = gateway.purchase(@amount, @credit_card, @options)
    assert_failure response
    assert_equal 'Required field vpc_Merchant was not present in the request', response.message
  end

  private

  def assert_response_match(regexp, url)
    response = https_response(url)
    assert_match regexp, response.body
  end

  def https_response(url, cookie = nil)
    retry_exceptions do
      headers = cookie ? {'Cookie' => cookie} : {}
      response = raw_ssl_request(:get, url, nil, headers)
      if response.is_a?(Net::HTTPRedirection)
        new_cookie = [cookie, response['Set-Cookie']].compact.join(';')
        response = https_response(response['Location'], new_cookie)
      end
      response
    end
  end
end
