class AccountController < ApplicationController
  def try_ssl_auth
    if request.env["SSL_CLIENT_CERT"]
      raw_client_cert = request.env["SSL_CLIENT_CERT"]
      cert = OpenSSL::X509::Certificate.new(raw_client_cert)
      subject_alt_name = cert.extensions.find {|e| e.oid == "subjectAltName"}
      if !subject_alt_name.nil?
        tmp = subject_alt_name.value.scan(/email:([^,]+),/).flatten
        session[:email] = tmp.first.downcase
      end
    end
    if session[:email]
      logger.info ">>> Login with certificate email: " + session[:email]
      user = User.find_by_mail(session[:email])
      # TODO: try to register on the fly
      unless user.nil?
      # Valid user
      return false if !user.active?
        user.update_attribute(:last_login_on, Time.now) if user && !user.new_record?
        self.logged_user = user
        return true
      end
    end
    return false
  end

  def ssl_login
    if params[:force_ssl]
      if try_ssl_auth
        redirect_back_or_default :controller => 'my', :action => 'page'
        return
      else
        render_403
        return
      end
    end
    if !User.current.logged? and not params[:skip_ssl]
      if try_ssl_auth
        redirect_back_or_default :controller => 'my', :action => 'page'
        return
      end
    end

    login
  end
end
