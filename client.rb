require 'rest-client'
require 'json'
require 'pp'
require 'yaml'

# TODO: separate
class ApsisNode
  def initialize(url, pubkey)
    @url = url
    @pubkey = pubkey
    @headers = {}
    @headers = {content_type: :json, accept: :json}
  end

  def get_random_nodes()
    @path = "/nodes/random"
    r = RestClient.get(url=@url+@path,
                       :params => {:pubkey => @pubkey},
                       :headers => @headers.merge({}))
    gen_response(r)
  end

  def post_node(payload)
    @path = '/nodes'
    r = RestClient.post(url=@url+@path,
                    payload.to_json,
                    headers=@headers.merge({}))
    gen_response(r)
  end

  private

  def gen_response(rest)
    fail Exception if rest.code >= 400
    {code: rest.code,
     cookies: rest.cookies,
     headers: rest.headers,
     body: rest.body}
  end
end

class Tinc
  def initialize(hosts_dir, node)
    @hosts_dir = hosts_dir
    @node = node
  end

  def pubkey()
    ed25519_token = 'Ed25519PublicKey = '
    File.open("#{@hosts_dir}/#{@node}") do |f|
      f.each_line do |l|
        if l.start_with?(ed25519_token)
          return l.slice(ed25519_token.length..l.length).chomp
        end
      end
    end
  end

  def host()
    node_file = ''
    File.open(@hosts_dir + '/' + @node) do |file|
      node_file = file.read
    end
    node_file
  end

  def write_host(file)
    #File.open(@hosts_dir + '/' + @node, "w") do |f|
    File.open('./' + @node, "w") do |f|
      f.puts(file)
    end
  end
end

config = YAML.load_file('config.yml')

t = Tinc.new(config['tinc']['dir'],config['tinc']['node'])

pubk = t.pubkey

an = ApsisNode.new(config['hub']['url'], pubk)

node = {keys: {ed25519: pubk}, file: t.host}

an.post_node(node) # publish own data to the server
candidate_nodes = an.get_random_nodes # fetch a random node
candidate_nodes

response = JSON.parse(candidate_nodes[:body])

# this tinc instance is ours
t = Tinc.new(config['tinc']['dir'], 'me')
t.write_host(response['file'])
