require 'sinatra'
require 'sinatra/google-auth'
require 'mail'

class JekyllAuth
  class AuthSite < Sinatra::Base
    
    # require ssl
    configure :production do
      require 'rack-ssl-enforcer'
      use Rack::SslEnforcer if JekyllAuth.ssl?
    end

    use Rack::Session::Cookie, {
      :http_only => true,
      :secret => ENV['SESSION_SECRET'] || SecureRandom.hex
    }
    
    register Sinatra::GoogleAuth
    
    before do
      pass if request.path_info.start_with?('/auth/google_oauth2')
      pass if JekyllAuth.whitelist && JekyllAuth.whitelist.match(request.path_info)
      authenticate
      if Mail::Address.new(session["user"]).domain != ENV['GOOGLE_EMAIL_DOMAIN']
        session["user"] = nil
        redirect request.path_info
      end
    end
    
    get '/logout' do
      session["user"] = nil
      redirect '/'
    end
  end
end
