# app.rb
require "sinatra"
require "redis"
require "jwt"
require 'red25519'
require 'base64'


redis = Redis.new(
  host: ENV["REDIS_HOST"],
  port: ENV["REDIS_PORT"]
)

set :bind, '0.0.0.0'

ecdsa_key = OpenSSL::PKey::EC.new File.read 'server_private.pem'
ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
ecdsa_public.private_key = nil

before '/nodes*' do
  if request.env['HTTP_AUTHORIZATION'] && request.env['HTTP_X_POW']
    begin
      @jwt_token = JWT.decode request.env["HTTP_AUTHORIZATION"].slice(7..-1), ecdsa_public, true, { :algorithm => 'ES256' }
      p Digest::SHA256.hexdigest(request.env['HTTP_X_POW'])
      p @jwt_token[0]['data']['challenge']
      if !Digest::SHA256.hexdigest(request.env['HTTP_X_POW']).start_with?(@jwt_token[0]['data']['challenge'])
        status 401
      end
    rescue JWT::ExpiredSignature
      status 401
    end
  else
    status 401
  end
end

get "/flush" do
  redis.flushdb
end

get "/dump" do
  keys = redis.keys('*')
  dump = []
  keys.each {  |key| dump.push(redis.get(key)) }
  dump
end

# registration of a new client
post "/nodes" do
  obj = JSON.parse request.body.read
  pubkey = obj['keys']['ed25519']
  obj['ip'] = request.ip
  if not redis.get(pubkey)
    redis.set(pubkey, obj.to_json)
    redis.expire(pubkey, 20)
  end
end


get "/nodes/random" do
  # A's (him/herself) pubkey
  pkey = params['pubkey']

  # check A's own hash
  logger.info "[PARAM] pkey="+pkey
  if myhash = redis.get(pkey)
    logger.info "[FOUND MYSELF] myhash="+myhash
    myobj = JSON.parse myhash
    if myobj.has_key?('pair')
      logger.info "[PAIR FOUND] myhash="+myhash
      return myobj['pair'].to_json
    end
  end

  cnt = 0
  found_pair = nil

  # exclude paired hash
  while not found_pair and cnt < 100
    pair_key = redis.randomkey
	#begin
	  if pair_cand = redis.get(pair_key)
        logger.info "[PAIR CANDIDATE] pair_cand="+pair_cand
        pair_cand_obj = JSON.parse pair_cand
	    if (pair_cand_obj['keys']['ed25519'] != pkey) and (not pair_cand_obj.has_key?(:pair))
          logger.info "[PAIR FOUND IN PAIR CANDIDATE] (my pubkey=#{pkey}), (pair pubkey=#{pair_key})"
	      found_pair = pair_cand_obj
	      found_pair[:pair] = myobj
	      redis.del(pkey)
          logger.info "[PAIR SET] #{found_pair.to_json}"
          redis.set(pair_key, found_pair.to_json)
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

post "/echo" do
  request.body.read
end

get "/jwt/challenge" do
  challenge = (0...4).map{ ["1","2","3","4","5","6","7","8","9","0","a","b","c","d","e","f",].sample }.join
  exp = Time.now.to_i + 20
  payload = { exp: exp, data: { pubkey: params['pubkey'], challenge: challenge } }

  token = JWT.encode payload, ecdsa_key, 'ES256'

#  pkey = Base64.urlsafe_decode64(params['pubkey'])
#  signing_key = Ed25519::VerifyKey.new(pkey)
end


