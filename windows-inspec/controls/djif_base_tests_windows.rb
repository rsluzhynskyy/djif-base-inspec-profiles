# Set additional flags to simplify checks management
kitchen = file('C:\Users\vagrant\AppData\Local\Temp\kitchen').exist?
win2012 = os.name.include?('2012')
cis_benchmark = win2012 ? 'cis-windows2012r2-level1-memberserver' : 'cis-windows2016rtm-release1607-level1-memberserver'

# Custom DJIF controls
control 'drive-label' do
  impact 1.0
  title 'drive-label'
  desc 'Check if C Drive label is set to System'

  script = <<-DRIVES
    [System.IO.DriveInfo]::GetDrives()
  DRIVES
  describe powershell(script) do
    its('stdout') { should match 'System' }
  end
end

control 'custom-files' do
  impact 1.0
  title  'Custom files and directories download check'
  desc   'Check if custom files and folders were created'

  %w[C:\buildinfo\build_files\tanium
     C:\cfn\scripts
     C:\temp\hardening
     C:\Windows\OEM].each do |dir|
    describe directory dir do
      it { should exist }
      its('owner') { should eq 'BUILTIN\\Administrators' }
    end
  end
end

control 'dj-certs' do
  impact 1.0
  title  'Installation of DJ Certificates'
  desc   'Check if DJ certs are installed'

  %w[djer-pem.crt
     djsn-pem.crt
     djte-pem.crt
     djgc-pem.crt
     djdi-pem.crt
     djsc-pem.crt].each do |cert|
    describe file("C:/buildinfo/build_files/#{cert}") do
      it { should exist }
      its('owner') { should eq 'BUILTIN\\Administrators' }
    end
  end
  # Check if DJ certs are installed in cert:\LocalComputer\Personal\Certificates
  describe command('certutil -store -v my') do
    its('stdout') { should match 'Trusted Entity' }
    its('stdout') { should match 'Secure Network' }
    its('stdout') { should match 'Secure Communication' }
    its('stdout') { should match 'Global Commerce' }
    its('stdout') { should match 'Digital Identity' }
  end
  # Check if "DJ ROOT CA" cert is appended to trusted certs
  describe file('C:\opscode\chef\embedded\ssl\certs\cacert.pem') do
    it { should exist }
    its('content') { should match(/DJ ROOT CA/) }
  end
end

control 'choco' do
  impact 1.0
  title  'Chocolatey check'
  desc   'Check if Chocolatey is installed'
  describe file('C:\ProgramData\chocolatey\bin\choco.exe') do
    it { should exist }
  end
end

control 'ntp' do
  impact 1.0
  title  'NTP check'
  desc   'Check if NTP client is installed/enabled/running'

  describe service('ntp') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'tanium' do
  impact 1.0
  title  'Tanium check'
  desc   'Check if Tanium client is installed'

  describe file('C:\buildinfo\build_files\tanium\TaniumClient-DJ-UNCONFIGURED-pre.msi') do
    it { should exist }
  end
  describe package('Tanium Client') do
    it { should be_installed }
  end
end

control 'crowdstrike' do
  impact 1.0
  title  'Crowdstrike installed'
  desc   'Check if crowdstrike`s installer is downloaded'

  # "Enabled" and "Running" is not applicable here as during installation
  # Because after the first start AID is created and it needs to be uniq.

  only_if { !kitchen }

  describe directory 'C:\buildinfo\build_files\crowdstrike' do
    it { should exist }
    its('owner') { should eq 'BUILTIN\\Administrators' }
  end
  describe file('C:\buildinfo\build_files\crowdstrike\WindowsSensor.exe') do
    it { should exist }
  end
end

control 'splunk-service' do
  impact 1.0
  title  'Splunk installed/disabled'
  desc   'Check if Splunk is installed/disabled'
  describe service('SplunkForwarder') do
    it { should be_installed }
    it { should_not be_enabled }
  end
end

control 'newrelic' do
  impact 1.0
  title  'Newrelic installed'
  desc   'Check if NewRelic is installed/enabled/running'

  describe service('newrelic-infra') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

include_controls 'windows-baseline' do
  # Skip these tests during local run, because we need to  be  able
  # to connect with non-administrator WinRM user to perform actions
  skip_control 'cis-network-access-2.2.2'
  skip_control 'windows-account-100'

  # Skip this check because it conflicts with xccdf_org.cisecurity.benchmarks_rule_2.3.11.7_L1
  skip_control 'windows-base-201'
end

include_controls cis_benchmark do
  # Skip these tests during the run, because  we  need to  be  able
  # to connect with non-administrator WinRM user to perform actions
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.2.2_L1_Configure_Access_this_computer_from_the_network'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Configure_Allow_log_on_through_Remote_Desktop_Services'

  # In AWS default user for  Windows  AMIs  is  Administrator,  so  if
  # we rename this user, Packer will lose connectivity to the instance
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_L1_Ensure_Accounts_Administrator_account_status_is_set_to_Disabled'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.5_L1_Configure_Accounts_Rename_administrator_account'

  # Need to skip this, if set - Packer gets timeout exceeded failure
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_9.3.1_L1_Ensure_Windows_Firewall_Public_Firewall_state_is_set_to_On_recommended'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_9.3.2_L1_Ensure_Windows_Firewall_Public_Inbound_connections_is_set_to_Block_default'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_9.3.3_L1_Ensure_Windows_Firewall_Public_Outbound_connections_is_set_to_Allow_default'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_9.3.4_L1_Ensure_Windows_Firewall_Public_Settings_Display_a_notification_is_set_to_Yes'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_9.3.5_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_firewall_rules_is_set_to_No'
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_9.3.6_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_connection_security_rules_is_set_to_No'

  # Packer uses basic authentication for WinRM, so we skip this check
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_18.9.86.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled'

  # Modify this check, because the name of the subcategory
  # is Plug  and  Play  Events  instead  of  PNP  Activity
  control 'xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success' do
    describe audit_policy do
      its('Plug and Play Events') { should eq 'Success' }
    end
  end

  # Modify next 3 controls because Inspec can't manage keys.with.periods,
  # changed  its('string')  to  its(['string'])  (put  string  to  array)
  # https://github.com/inspec/inspec/issues/1281
  control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.3_L1_Ensure_Default_Protections_for_Internet_Explorer_is_set_to_Enabled' do
    describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
      it { should have_property '*\Internet Explorer\iexplore.exe' }
      its(['*\Internet Explorer\iexplore.exe']) { should eq '+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2' }
    end
  end
  control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.4_L1_Ensure_Default_Protections_for_Popular_Software_is_set_to_Enabled' do
    describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
      it { should have_property '*\Mozilla Thunderbird\thunderbird.exe' }
      its(['*\Mozilla Thunderbird\thunderbird.exe']) { should match(//) }
    end
  end
  control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.5_L1_Ensure_Default_Protections_for_Recommended_Software_is_set_to_Enabled' do
    describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
      it { should have_property '*\Java\jre*\bin\javaws.exe' }
      its(['*\Java\jre*\bin\javaws.exe']) { should eq '-HeapSpray' }
    end
  end

  if win2012
    # [2012 only] Skip this check, because it requires WinRM lock on Windows 2012
    skip_control 'xccdf_org.cisecurity.benchmarks_rule_18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled_MS_only'
  end
end
