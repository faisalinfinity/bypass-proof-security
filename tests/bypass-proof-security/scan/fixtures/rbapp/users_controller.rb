class UsersController < ApplicationController
  skip_before_action :verify_authenticity_token                                   # EXPECT csrf-disabled
  def update; User.find(params[:id]).update(params.require(:user).permit!); end   # EXPECT mass-assignment
  def search; User.where("name = '#{params[:q]}'"); end                           # EXPECT sqli-interpolated
  def back; redirect_to params[:next]; end                                        # EXPECT open-redirect
  def load; Marshal.load(Base64.decode64(cookies[:x])); end                       # EXPECT unsafe-deserialization
end
