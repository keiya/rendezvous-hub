# app.rb
require "sinatra"
require "redis"
require "jwt"

set :bind, '0.0.0.0'

configure do
  ecdsa_key = OpenSSL::PKey::EC.new File.read 'server_private.pem'
  ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
  ecdsa_public.private_key = nil

  set :ecdsa_key, ecdsa_key
  set :ecdsa_public, ecdsa_public
  set :redis, Redis.new(
    host: ENV["REDIS_HOST"],
    port: ENV["REDIS_PORT"]
  )
end

def get_node(pubkey)
  node = settings.redis.get(pubkey)
  if node
    JSON.parse node
  else
    nil
  end
end

def set_node(pubkey, node)
  node_json = node.to_json
  settings.redis.set(pubkey, node_json)
  settings.redis.expire(pubkey, 60)
  node_json
end

def gen_jwt(ctr=0)
  challenge = (0...4).map{ ["1","2","3","4","5","6","7","8","9","0","a","b","c","d","e","f",].sample }.join
  exp = Time.now.to_i + 20
  payload = { exp: exp, data: { pubkey: @pubkey, challenge: challenge, ctr: ctr } }
  token = JWT.encode payload, settings.ecdsa_key, 'ES256'
end

before do
  content_type :json

  if request.env['HTTP_AUTHORIZATION']
    @jwt_token = JWT.decode request.env["HTTP_AUTHORIZATION"].slice(7..-1), settings.ecdsa_public, true, { :algorithm => 'ES256' }
    p @jwt_token
  end

  if params['pubkey']
    @pubkey = params['pubkey']
  elsif not @jwt_token.nil?
    @pubkey = @jwt_token[0]['data']['pubkey']
  else
    return
  end
end

before '/nodes*' do
  next_ctr =  + 1

  node = get_node(@pubkey)
  p node

  if node.nil?
    node = {}
    node['ctr'] = 1
  else
    if node['ctr'] != @jwt_token[0]['data']['ctr']
      halt 400
    end
    node['ctr'] += 1
  end
  set_node(@pubkey, node)

  response.headers['X-Jwt'] = gen_jwt node['ctr']

  if request.env['HTTP_X_POW']
    begin
      p Digest::SHA256.hexdigest(request.env['HTTP_X_POW'])
      p @jwt_token[0]['data']['challenge']
      if !Digest::SHA256.hexdigest(request.env['HTTP_X_POW']).start_with?(@jwt_token[0]['data']['challenge'])
        halt 401
      end
    rescue JWT::ExpiredSignature
      halt 401
    end
  else
    halt 401
  end
end

get "/flush" do
  settings.redis.flushdb
end

get "/dump" do
  keys = settings.redis.keys('*')
  dump = {}
  keys.each {  |key| dump[key] = JSON.parse settings.redis.get(key) }
  dump.to_json
end

# registration of a new client
post "/nodes" do
  reqbody = JSON.parse request.body.read
  pubkey = reqbody['keys']['ed25519']
  node = get_node(pubkey)
  if node.dig('user','pair','user').nil?
    node['user'] = reqbody
    node['user']['ip'] = request.ip
    set_node(pubkey,node)
  end
end


get "/nodes/random" do
  # check A's own hash
  logger.info "[PARAM] @pubkey="+@pubkey
  if myobj = get_node(@pubkey)
    logger.info "[FOUND MYSELF]"
    if myobj['user'].has_key?('pair')
      logger.info "[PAIR FOUND] myhash="+myobj['user']['pair'].to_json
	  settings.redis.del(@pubkey)
      return myobj.dig('user','pair','user').to_json
    end
  end

  cnt = 0
  found_pair = {}

  # exclude paired hash
  while found_pair.empty? and cnt < 100
    pair_key = settings.redis.randomkey
	#begin
	  if pair_cand = get_node(pair_key)
        cand_key = pair_cand.dig('user','keys','ed25519')
	    if (not cand_key.nil?) and (cand_key != @pubkey) and (not pair_cand['user'].has_key?(:pair))
          logger.info "[PAIR FOUND IN PAIR CANDIDATE] (my pubkey=#{@pubkey}), (pair pubkey=#{pair_key})"
	      found_pair = pair_cand
	      found_pair['user'][:pair] = myobj
	      settings.redis.del(@pubkey)
          set_node(pair_key, found_pair)
          found_pair['user'].delete(:pair)
	    end
	  end
	#rescue JSON::ParserError
	#end
	cnt += 1
  end

  found_pair.dig('user').to_json
end

get "/nodes/debug" do
  random = settings.redis.randomkey
  settings.redis.get(random)
end

post "/echo" do
  request.body.read
end

get "/jwt/challenge" do
  response.headers['X-Jwt'] = gen_jwt
  nil
end


