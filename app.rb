# app.rb
require "sinatra"
require "redis"
require "jwt"

redis = Redis.new(
  host: ENV["REDIS_HOST"],
  port: ENV["REDIS_PORT"]
)

set :bind, '0.0.0.0'

#before do
#  request.body.rewind
##  begin
##  @request_payload = JSON.parse request.body.read
##  rescue
##  @request_payload = nil
##  end
##  @jwt = JWT.decode request.env["Authorization"] if request.env.has_key?('Authorization')
#  @request_payload = request.body.read
#end

get "/flush" do
  redis.flushdb
end

get "/dump" do
redis.keys('*')
end

# registration of a new client
post "/nodes" do
  obj = JSON.parse request.body.read
  pubkey = obj["keys"]["ed25519"]
  redis.set(pubkey, obj.to_json)
  redis.expire(pubkey, 20)
end


get "/nodes/random" do
  # A's (him/herself) pubkey
  pkey = params['pubkey']

  # check A's own hash
  if myhash = redis.get(pkey)
    myobj = JSON.parse myhash
    if myobj and myobj.has_key?(:pair)
      return myobj[:pair].to_json
    end
  end

  cnt = 0
  found_pair = nil

  # exclude paired hash
  while not found_pair and cnt < 100
    pair_key = redis.randomkey
	#begin
	  if pair_cand = redis.get(pair_key)
        pair_cand_obj = JSON.parse pair_cand
	    if not pair_cand_obj.has_key?(:pair)
	      found_pair = pair_cand_obj
	      found_pair[:pair] = myobj
	      redis.del(pkey)
          redis.getset(pair_key, found_pair.to_json)
          redis.expire(pair_key, 20) # TODO: calculate expire
	    end
	  end
	#rescue JSON::ParserError
	#end
	cnt += 1
  end

  found_pair.to_json
end

get "/nodes/debug" do
  random = redis.randomkey
redis.get(random)

end
