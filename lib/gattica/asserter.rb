require 'google/api_client'

module Gattica

  # Represents a user to be authenticated by GA

  class Asserter
    attr_accessor :email, :pkcs12_path

    def initialize(email,pkcs12_path)
      @email = email
      @pkcs12_path = pkcs12_path
      validate
    end

    def access_token
      @access_token ||= begin
        key = ::Google::APIClient::PKCS12.load_key(pkcs12_path, 'notasecret')
        asserter = ::Google::APIClient::JWTAsserter.new(email, 'https://www.googleapis.com/auth/analytics', key)
        asserter.authorize.access_token
      end
    end

    private
    # Determine whether or not this is a valid user
    def validate
      raise GatticaError::InvalidEmail, "The email address '#{@email}' is not valid" if not @email.match(/^(?:[_a-z0-9-]+)(\.[_a-z0-9-]+)*@([a-z0-9-]+)(\.[a-zA-Z0-9\-\.]+)*(\.[a-z]{2,4})$/i)
      raise GatticaError::InvalidPkcs12Path, "The pkcs12_path cannot be blank" if @pkcs12_path.empty? || @pkcs12_path.nil? || (@pkcs12_path && !File.exists?(@pkcs12_path))
    end
  end
end
