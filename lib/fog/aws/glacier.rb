require 'fog/aws'
require 'fog/storage'

module Fog
  module Storage
    class Glacier < Fog::Service
      extend Fog::AWS::CredentialFetcher::ServiceMethods

      requires :aws_access_key_id, :aws_secret_access_key
      recognizes :endpoint, :region, :host, :path, :port, :scheme, :persistent, :use_iam_profile, :aws_session_token, :aws_credentials_expire_at

      secrets    :aws_secret_access_key, :hmac

# TODO: Make these models
      model_path 'fog/aws/models/glacier'
      collection  :vaults
      model       :vault
      collection  :archives
      model       :archive

# TODO: Make these requests
      request_path 'fog/aws/requests/glacier'
      # Following http://docs.amazonwebservices.com/amazonglacier/latest/dev/api-multipart-complete-upload.html

      request :create_vault
      request :delete_vault
      request :describe_vault
      request :list_vaults
      request :put_notification_configuration
      request :get_vault_notifications
      request :delete_vault_notifications
      request :upload_archive
      request :delete_archive

      request :initiate_multipart_upload
      request :upload_part
      request :complete_multipart_upload
      request :abort_multipart_upload
      request :list_parts
      request :list_multipart_uploads



      request :initiate_job
      request :describe_job
      request :get_job_output
      request :list_jobs


# TODO: I don't think we're using a CDN, delete this part?
      module Utils

        attr_accessor :region

        def cdn
          @cdn ||= Fog::AWS::CDN.new(
            :aws_access_key_id => @aws_access_key_id,
            :aws_secret_access_key => @aws_secret_access_key,
            :use_iam_profile => @use_iam_profile
          )
        end

        def http_url(params, expires)
          scheme_host_path_query(params.merge(:scheme => 'http', :port => 80), expires)
        end

        def https_url(params, expires)
          scheme_host_path_query(params.merge(:scheme => 'https', :port => 443), expires)
        end

        def url(params, expires)
          Fog::Logger.deprecation("Fog::Storage::AWS => #url is deprecated, use #https_url instead [light_black](#{caller.first})[/]")
          https_url(params, expires)
        end

        private

        def scheme_host_path_query(params, expires)
          params[:scheme] ||= @scheme
          if params[:port] == 80 && params[:scheme] == 'http'
            params.delete(:port)
          end
          if params[:port] == 443 && params[:scheme] == 'https'
            params.delete(:port)
          end
          params[:headers] ||= {}
          params[:headers]['Date'] = expires.to_i
          params[:path] = Fog::AWS.escape(params[:path]).gsub('%2F', '/')
          query = []
          params[:headers]['x-amz-security-token'] = @aws_session_token if @aws_session_token
          if params[:query]
            for key, value in params[:query]
              query << "#{key}=#{Fog::AWS.escape(value)}"
            end
          end
          query << "AWSAccessKeyId=#{@aws_access_key_id}"
          query << "Signature=#{Fog::AWS.escape(signature(params))}"
          query << "Expires=#{params[:headers]['Date']}"
          query << "x-amz-security-token=#{Fog::AWS.escape(@aws_session_token)}" if @aws_session_token
          port_part = params[:port] && ":#{params[:port]}"
          "#{params[:scheme]}://#{params[:host]}#{port_part}/#{params[:path]}?#{query.join('&')}"
        end

      end

# TODO: What is this Mock?
      class Mock
        include Utils

        def self.acls(type)
          case type
          when 'private'
            {
              "AccessControlList" => [
                {
                  "Permission" => "FULL_CONTROL",
                  "Grantee" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
                }
              ],
              "Owner" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
            }
          when 'public-read'
            {
              "AccessControlList" => [
                {
                  "Permission" => "FULL_CONTROL",
                  "Grantee" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
                },
                {
                  "Permission" => "READ",
                  "Grantee" => {"URI" => "http://acs.amazonaws.com/groups/global/AllUsers"}
                }
              ],
              "Owner" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
            }
          when 'public-read-write'
            {
              "AccessControlList" => [
                {
                  "Permission" => "FULL_CONTROL",
                  "Grantee" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
                },
                {
                  "Permission" => "READ",
                  "Grantee" => {"URI" => "http://acs.amazonaws.com/groups/global/AllUsers"}
                },
                {
                  "Permission" => "WRITE",
                  "Grantee" => {"URI" => "http://acs.amazonaws.com/groups/global/AllUsers"}
                }
              ],
              "Owner" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
            }
          when 'authenticated-read'
            {
              "AccessControlList" => [
                {
                  "Permission" => "FULL_CONTROL",
                  "Grantee" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
                },
                {
                  "Permission" => "READ",
                  "Grantee" => {"URI" => "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}
                }
              ],
              "Owner" => {"DisplayName" => "me", "ID" => "2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"}
            }
          end
        end

        def self.data
          @data ||= Hash.new do |hash, region|
            hash[region] = Hash.new do |region_hash, key|
              region_hash[key] = {
                :acls => {
                  :bucket => {},
                  :object => {}
                },
                :buckets => {}
              }
            end
          end
        end

        def self.reset
          @data = nil
        end

# http://docs.amazonwebservices.com/general/latest/gr/rande.html#glacier_region
#  Amazon Glacier
#  Region  Endpoint    Protocol
#  US East (Northern Virginia) Region  glacier.us-east-1.amazonaws.com HTTP and HTTPS
#  US West (Oregon) Region glacier.us-west-2.amazonaws.com HTTP and HTTPS
#  US West (Northern California) Region    glacier.us-west-1.amazonaws.com HTTP and HTTPS
#  EU (Ireland) Region glacier.eu-west-1.amazonaws.com HTTP and HTTPS
#  Asia Pacific (Tokyo) Region glacier.ap-northeast-1.amazonaws.com    HTTP and HTTPS

        def initialize(options={})
          require 'mime/types'
          @use_iam_profile = options[:use_iam_profile]
          options[:region] ||= 'us-east-1'
          setup_credentials(options)
          @host = options[:host] || case options[:region]
          when 'us-east-1'
            'glacier.us-east-1.amazonaws.com'
          else
            "glacier.#{options[:region]}.amazonaws.com"
          end
          @scheme = options[:scheme] || 'https'
          @region = options[:region]
        end

        def data
          self.class.data[@region][@aws_access_key_id]
        end

        def reset_data
          self.class.data[@region].delete(@aws_access_key_id)
        end

        def signature(params)
          "foo"
        end

        def setup_credentials(options)
          @aws_access_key_id = options[:aws_access_key_id]
          @aws_secret_access_key = options[:aws_secret_access_key]
          @aws_session_token     = options[:aws_session_token]
          @aws_credentials_expire_at = options[:aws_credentials_expire_at]
        end

      end

      class Real
        include Utils
        include Fog::AWS::CredentialFetcher::ConnectionMethods
        # Initialize connection to S3
        #
        # ==== Notes
        # options parameter must include values for :aws_access_key_id and
        # :aws_secret_access_key in order to create a connection
        #
        # ==== Examples
        #   s3 = Fog::Storage.new(
        #     :provider => "AWSGlacier",
        #     :aws_access_key_id => your_aws_access_key_id,
        #     :aws_secret_access_key => your_aws_secret_access_key
        #   )
        #
        # ==== Parameters
        # * options<~Hash> - config arguments for connection.  Defaults to {}.
        #
        # ==== Returns
        # * S3 object with connection to aws.
        def initialize(options={})
          require 'fog/core/parser'
          require 'mime/types'

          @use_iam_profile = options[:use_iam_profile]
          # this needs to be done after region is determined: setup_credentials(options)
          @connection_options     = options[:connection_options] || {}
          
# http://docs.amazonwebservices.com/general/latest/gr/rande.html#glacier_region
#  Amazon Glacier
#  Region  Endpoint    Protocol
#  US East (Northern Virginia) Region  glacier.us-east-1.amazonaws.com HTTP and HTTPS
#  US West (Oregon) Region glacier.us-west-2.amazonaws.com HTTP and HTTPS
#  US West (Northern California) Region    glacier.us-west-1.amazonaws.com HTTP and HTTPS
#  EU (Ireland) Region glacier.eu-west-1.amazonaws.com HTTP and HTTPS
#  Asia Pacific (Tokyo) Region glacier.ap-northeast-1.amazonaws.com    HTTP and HTTPS
          if @endpoint = options[:endpoint]
            endpoint = URI.parse(@endpoint)
            @host = endpoint.host
            @path = if endpoint.path.empty?
              '/'
            else
              endpoint.path
            end
            @port = endpoint.port
            @scheme = endpoint.scheme
          else
            options[:region] ||= 'us-east-1'
            @region = options[:region]
            @host = options[:host] || case options[:region]
            when 'us-east-1'
              'glacier.us-east-1.amazonaws.com'
            else
              "glacier.#{options[:region]}.amazonaws.com"
            end
            @path       = options[:path]        || '/'
            @persistent = options.fetch(:persistent, false)
            @port       = options[:port]        || 443
            @scheme     = options[:scheme]      || 'https'
          end
        # TODO: what if we get an @endpoint and no region is set?
          setup_credentials(options)
          @connection = Fog::Connection.new("#{@scheme}://#{@host}:#{@port}#{@path}", @persistent, @connection_options)
        end

        def reload
          @connection.reset
        end

    # TODO: Check signature conforms to : http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
    #    CanonicalRequest =
    #      HTTPRequestMethod + '\n' +
    #      CanonicalURI + '\n' +
    #      CanonicalQueryString + '\n' +
    #      CanonicalHeaders + '\n' +
    #      SignedHeaders + '\n' +
    #      HexEncode(Hash(Payload))

    # Note: Verify against test suite: http://docs.amazonwebservices.com/general/latest/gr/signature-v4-test-suite.html

    # Note: Consider leveraging: https://github.com/amazonwebservices/aws-sdk-for-ruby/tree/master/lib

        def signature(params)
          string_to_sign =
<<-DATA
#{params[:method].to_s.upcase}
#{params[:headers]['Canonical-URI']}
#{params[:headers]['Canonical-QueryString']}
#{params[:headers]['Canonical-Headers']}
#{params[:headers]['Signed-Headers']}
#{params[:headers]['Hex-Encode-Hash-Payload']}
DATA

          amz_headers, canonical_amz_headers = {}, ''
          for key, value in params[:headers]
            if key[0..5] == 'x-amz-'
              amz_headers[key] = value
            end
          end
          amz_headers = amz_headers.sort {|x, y| x[0] <=> y[0]}
          for key, value in amz_headers
            canonical_amz_headers << "#{key}:#{value}\n"
          end
          string_to_sign << canonical_amz_headers

          subdomain = params[:host].split(".#{@host}").first
          unless subdomain =~ /^(?:[a-z]|\d(?!\d{0,2}(?:\.\d{1,3}){3}$))(?:[a-z0-9]|\.(?![\.\-])|\-(?![\.])){1,61}[a-z0-9]$/
        # TODO: err..... not sure if this is needed
            Fog::Logger.warning("fog: the specified glacier vault name(#{subdomain}) is not a valid dns name, which will negatively impact performance.  For details see: http://docs.amazonwebservices.com/AmazonS3/latest/dev/BucketRestrictions.html")
            params[:host] = params[:host].split("#{subdomain}.")[-1]
            if params[:path]
              params[:path] = "#{subdomain}/#{params[:path]}"
            else
              params[:path] = subdomain
            end
            subdomain = nil
          end

          canonical_resource  = @path.dup
          unless subdomain.nil? || subdomain == @host
            canonical_resource << "#{Fog::AWS.escape(subdomain).downcase}/"
          end
          canonical_resource << params[:path].to_s
          canonical_resource << '?'
# TODO: all these keys need to change to reflect glacier
          for key in (params[:query] || {}).keys.sort
            if %w{
              acl
              lifecycle
              location
              logging
              notification
              partNumber
              policy
              requestPayment
              response-cache-control
              response-content-disposition
              response-content-encoding
              response-content-language
              response-content-type
              response-expires
              torrent
              uploadId
              uploads
              versionId
              versioning
              versions
              website
            }.include?(key)
              canonical_resource << "#{key}#{"=#{params[:query][key]}" unless params[:query][key].nil?}&"
            end
          end
          canonical_resource.chop!
          string_to_sign << canonical_resource

          signed_string = @hmac.sign(string_to_sign)
          Base64.encode64(signed_string).chomp!
        end

        private

        def setup_credentials(options)
          @aws_access_key_id     = options[:aws_access_key_id]
          @aws_secret_access_key = options[:aws_secret_access_key]
          @aws_session_token     = options[:aws_session_token]
          @aws_credentials_expire_at = options[:aws_credentials_expire_at]


#       http://docs.amazonwebservices.com/general/latest/gr/sigv4-calculate-signature.html
#       kSecret = Your AWS Secret Access Key
#       kDate = HMAC("AWS4" + kSecret, Date)
#       kRegion = HMAC(kDate, Region)
#       kService = HMAC(kRegion, Service)
#       kSigning = HMAC(kService, "aws4_request")
#       Use the derived key (kSigning) to sign your canonical message rather than your AWS Secret Access Key. The following example shows pseudocode for the derivation of a key for signing requests to IAM in the us-east-1 region on February 28, 2012.
#       HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,"20120228"),"us-east-1"),"iam"),"aws4_request")

          kDate = Time.now.strftime("%Y%m%d")
          kRegion = options[:region]
          @aws_v4_key = HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,kDate),kRegion),"glacier"),"aws4_request")

          # SHA256 required for AWS Signature v4
          @hmac = Fog::HMAC.new('sha256', @aws_v4_key)
        end

        def request(params, &block)
          refresh_credentials_if_expired

          params[:headers]['Date'] = Fog::Time.now.to_date_header
          params[:headers]['x-amz-security-token'] = @aws_session_token if @aws_session_token
          params[:headers]['Authorization'] = "AWS #{@aws_access_key_id}:#{signature(params)}"
          # FIXME: ToHashParser should make this not needed
          original_params = params.dup

          begin
            response = @connection.request(params, &block)
          rescue Excon::Errors::TemporaryRedirect => error
            uri = URI.parse(error.response.headers['Location'])
            Fog::Logger.warning("fog: followed redirect to #{uri.host}, connecting to the matching region will be more performant")
            response = Fog::Connection.new("#{@scheme}://#{uri.host}:#{@port}", false, @connection_options).request(original_params, &block)
          end

          response
        end
      end
    end
  end
end
