require 'dotenv/load'
require "workos"
require "sinatra"
require "json"

WorkOS.configure do |config|
  config.key = ENV['WORKOS_API_KEY']
end

client_id = ENV['WORKOS_CLIENT_ID']
cookie_password = ENV['WORKOS_COOKIE_PASSWORD']

set :port, 3000
set :bind, 'localhost'

helpers do
  def load_session(client_id, cookie_password)
    WorkOS::UserManagement.load_sealed_session(
      client_id: client_id,
      session_data: request.cookies["wos_session"],
      cookie_password: cookie_password,
    )
  end

  def with_auth(request, response, client_id, cookie_password)
    session = load_session(client_id, cookie_password)
    session.authenticate() => { authenticated:, reason: }
    return if authenticated == true

    redirect "/login" if !authenticated && reason == "NO_SESSION_COOKIE_PROVIDED"

    # If no session, attempt a refresh
    begin
      result = session.refresh()
      redirect "/login" if !result[:authenticated]
      response.set_cookie("wos_session", value: result[:sealed_session], httponly: true, secure: true, samesite: "lax")
      redirect request.url
    rescue StandardError => e
      puts e
      response.delete_cookie("wos_session")
      redirect "/login"
    end
  end
end

get "/" do
  session = load_session(client_id, cookie_password)
  result = session.authenticate
  @current_user = result[:authenticated] ? result[:user] : nil
  erb :index, :layout => :layout
end

get "/login" do
  puts "wat #{ENV['WORKOS_REDIRECT_URI']}"
  authorization_url = WorkOS::UserManagement.authorization_url(
    provider: "authkit",
    client_id: client_id,
    redirect_uri: ENV['WORKOS_REDIRECT_URI'],
  )

  redirect authorization_url
end

get "/callback" do
  code = params["code"]

  begin
    auth_response = WorkOS::UserManagement.authenticate_with_code(
      client_id: client_id,
      code: code,
      session: { :seal_session => true, :cookie_password => cookie_password }
    )

    # store the session in a cookie
    response.set_cookie("wos_session", value: auth_response.sealed_session, httponly: true, secure: true, samesite: "lax")
    redirect "/"
  rescue StandardError => e
    puts e
    redirect "/login"
  end
end

get "/account" do
  with_auth(request, response, client_id, cookie_password)
  session = load_session(client_id, cookie_password)
  result = session.authenticate
  @current_user = result[:authenticated] ? result[:user] : nil
  erb :account, :layout => :layout
end

get "/logout" do
  session = load_session(client_id, cookie_password)
  url = session.get_logout_url()
  response.delete_cookie("wos_session")
  # After log out has succeeded, the user will be redirected to your app homepage which is configured in the WorkOS dashboard
  redirect url
end