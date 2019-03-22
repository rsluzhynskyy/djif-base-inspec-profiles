# Below are controls against windows_iis.rb
# it checks if required IIS features and services are installed.
win2012 = os.name.include?('2012')

control 'iis-msmq-features' do
  impact 1.0
  title 'IIS/MSMQ features installation check'
  desc 'IIS and MSMQ are installed'
  %w[MSMQ
     MSMQ-Services
     MSMQ-Server
     Web-WebServer
     Web-Mgmt-Tools
     Web-Mgmt-Console
     Web-Mgmt-Compat
     Web-Scripting-Tools
     Web-Mgmt-Service].each do |ftr|
    describe windows_feature(ftr) do
      it { should be_installed }
    end
  end
end

control 'iis-msmq-services' do
  impact 1.0
  title 'IIS/MSMQ features installation check'
  desc 'IIS and MSMQ are installed'
  %w[MSMQ W3SVC].each do |srv|
    describe service(srv) do
      it { should be_installed }
      it { should_not be_enabled }
    end
  end
end

control 'ec2-config-service' do
  impact 1.0
  title  'EC2Config Service check'
  desc   'Check if EC2ConfigService is installed'

  only_if { win2012 }

  describe package('EC2ConfigService') do
    it { should be_installed }
  end
end

control 'ec2-windows-launch' do
  impact 1.0
  title  'EC2-Windows-Launch check'
  desc   'Check if EC2Launch scripts are downloaded'

  only_if { !win2012 }

  describe file('C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\InitializeInstance.ps1') do
    it { should exist }
  end
end

control 'aws-pv-drivers' do
  impact 1.0
  title  'AWSPV Drivers check'
  desc   'Check if AWS PV Drivers are installed'
  describe package('AWS PV Drivers') do
    it { should be_installed }
  end
end

control 'aws-tools' do
  impact 1.0
  title  'AWSTools check'
  desc   'Check if AWSTools is installed'
  describe package('AWS Tools for Windows') do
    it { should be_installed }
  end
end

control 'aws-cfn-bootstrap' do
  impact 1.0
  title  'AWSCFNBootstrap check'
  desc   'Check if AWSCFNBootstrap is installed'
  describe package('aws-cfn-bootstrap') do
    it { should be_installed }
  end
end

control 'dotnet-4.7.2' do
  impact 1.0
  title  'dotnet4.7.2 check'
  desc   'Check if dotnet4.7.2 is installed'
  describe command('C:\ProgramData\chocolatey\bin\choco.exe list --local-only') do
    its('stdout') { should match 'dotnet4.7.2' }
  end
end
