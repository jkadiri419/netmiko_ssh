import re
import os
from time import sleep
import subprocess

from CONNECTIONS.CONNECTIONS import createConnection, disconnectSSHConnection, runCmd, clearBuffer, readChannel, sendCmds, sftpRunCmd
from CONNECTIONS.CONNECTIONS import transferFile as tf
from LOGGER import log
import GLOBALS.GLOBALS as GLOBALS

# HOLD AUDIT-TRAIL COMMAND
AUDIT_TRAIL_COMMAND = list()

# POSSIBLE ERRORS WHILE SENDING SHOW/SYSTEM COMMAND
SYNTAX_ERROR_ELE_NOT_EXISTS = re.compile(r"syntax error: element does not exist", re.I)
ERROR_FAILED_TO_OPEN_FILE = re.compile(r"Error: failed to open file: File/directory does not exist.", re.I)

# POSSIBLE ERRORS WHILE SENDING SHOW/SYSTEM COMMAND AND CONFIG COMMAND
SYNTAX_ERROR_UA = re.compile(r"syntax error: unknown argument", re.I)
SYNTAX_ERROR_UE = re.compile(r"syntax error: unknown element", re.I)
SYNTAX_ERROR_BL = re.compile(r"syntax error: .*bad length/size", re.I)
ERROR_FAILED_AM = re.compile(r"Error: failed to apply modifications", re.I)

# POSSIBLE ERRORS WHILE SENDING CONFIG COMMAND
SYNTAX_ERROR_IP = re.compile(r"syntax error: incomplete path", re.I)
ERROR_FILE_NOT_EXISTS = re.compile(r"error-message 'File does not exist'", re.I)
ERROR_CANNOT_DELETE_AUDIT_TRAIL_FILE = re.compile(r"error-message 'Cannot delete running audit-trail file", re.I)
INVALID_DESTINATION = re.compile(f"Invalid destination file", re.I)
PERMISSION_DENIED = re.compile(r"Aborted: permission denied", re.I)
FILE_NOT_EXISTS=re.compile(r'No such file or directory', re.I)
SYNTAX_ERROR_OOR = re.compile(r'syntax error: "(\d+)" is out of range.', re.I)
NODE_READONLY = re.compile(r'Aborted: node is in readonly mode')
INVALID_CRASH_ID = re.compile(r'Invalid Crash Id:', re.I)

ERROR_PATTERNS = [SYNTAX_ERROR_IP, ERROR_FILE_NOT_EXISTS, ERROR_CANNOT_DELETE_AUDIT_TRAIL_FILE, INVALID_DESTINATION, 
                  PERMISSION_DENIED, FILE_NOT_EXISTS, SYNTAX_ERROR_OOR, NODE_READONLY, ERROR_FAILED_AM, SYNTAX_ERROR_UA, 
                  SYNTAX_ERROR_UE, SYNTAX_ERROR_BL, SYNTAX_ERROR_ELE_NOT_EXISTS, ERROR_FAILED_TO_OPEN_FILE, INVALID_CRASH_ID]

def determinePassword(gwpp_info, sshUser="admin", sshPassword=os.environ['gwppPASSWORD']):

    """
    In R6.0, gwpp admin policy has been introduced and applied. This policy enforce user to change the password accroding
    the policy configured on gwpp. default IS 90 days, means In every 90 days User needs to change the password.
    A list of 3 password would maintain in JSON, becasue as per policy previous password can not repeat.
    This method would determine current active password on gwpp, and publish to environment, so rest execution can use this
    password

    Attributes:
    -----------
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....
    sshUser : str, Username to login to M/C [ admin/configadmin/superadmin, default: admin ]
    sshPassword: str, default password, initialise @ run_test

    Return:
    -------

    0 upon successfull , otherwise 'abort' the execution

    Usage:
    ------

        determinePassword(gwpp_info)

    """

    # HARDCODE 'admin' PASSWORD AS PER TES-7265
    gwpp_info['admin_passwords'] = ['gwpp@111', 'Parallel$222', 'Cloud&333']

    log.print(gwpp_info)
    # gwpp DEFAULT PORT
    sshPort = 22
    # gwpp IDENTIFIER
    sshId = gwpp_info["gwpp_id"]
    # CHECK WITH 'default' PASSWORD
    status = createConnection(gwpp_info['mgmt-ip-p'], sshUser, sshPassword, sshPort, sshId)
    # IF 'SUCCESS' CHECK FOR 'standby' TOO
    if status and os.environ["REDUNDANCY"] == 'True':
        status = createConnection(gwpp_info['mgmt-ip-s'], sshUser, sshPassword, sshPort, sshId)
        log.info(f'SUCCESSFULLY LOGGED TO gwpp WITH PASSWORD: [{sshPassword}]')

    # IF NOT 'SUCCESSFUL' TRY WITH REST OF 'PASSWORD'
    if not status:
        for password in gwpp_info['admin_passwords']:
            status = createConnection(gwpp_info['mgmt-ip-p'], sshUser, password, sshPort, sshId)
            if status and os.environ["REDUNDANCY"] == 'True':
                createConnection(gwpp_info['mgmt-ip-s'], sshUser, password, sshPort, sshId)
                os.environ['gwppPASSWORD'] = password
                log.info(f'SUCCESSFULLY LOGGED TO gwpp WITH PASSWORD: [{password}]')
                break
        if not status:
            log.abort(f'UNABLE TO LOGIN TO gwpps WITH ANY OF THE PROVIDED PASSWORDs: [{sshPassword}/{gwpp_info["admin_passwords"]}]')

    # SEE IF PASSWORD REQUIRED TO CHANGE
    sshConnectionName = "{}_{}_{}".format(gwpp_info['mgmt-ip-p'], sshUser, sshId)
    sshSessionLog = "/tmp/ssh_{}.txt".format(sshConnectionName)
    pwdInfo = subprocess.run(["egrep", "-e", r"(Password Changed .* change)", "-o", sshSessionLog],
                              stdout=subprocess.PIPE,
                              text=True,
    )
    log.info(f'PASSWORD INFORMATION [{pwdInfo.stdout.strip()}]')

    # DAYS REMAINS TO EXPIRE?
    if len(pwdInfo.stdout):
        # Password Changed On 2020-09-30 21 days left to change
        days = re.findall(r"\d+-\d+-\d+ (\d+) days left to change", pwdInfo.stdout)
        passwordChangeStatus = 0
        if days and int(days[0]) <= 5:
            log.warning(f'PASSWORD CHANGE REQUIRED, AS IT IS ABOUT TO EXPIRE IN: [{days[0]}]')
            # DETERMINE NEXT PASSWORD
            # ADD FIRST PASSWORD TO THE LAST AS WELL
            gwpp_info['admin_passwords'].append(gwpp_info['admin_passwords'][0])
            # ADD 'admin' TO FIRST INDEX TO AVOID 'ValueError'
            gwpp_info['admin_passwords'].insert(0, os.environ['gwppPASSWORD'])
            currentPasswordIndex = gwpp_info['admin_passwords'].index(os.environ['gwppPASSWORD'])
            nextPossiblePassword = gwpp_info['admin_passwords'][currentPasswordIndex+1]
            log.warning(f'ATTEMPTING TO CHANGE EXISTING PASSWORD: [{os.environ["gwppPASSWORD"]}] TO [{nextPossiblePassword}]')
            passwordChangeCmd = ('secure-user change-password' + f' old-password {os.environ["gwppPASSWORD"]}' +
                                 f' new-password {nextPossiblePassword} confirm-password {nextPossiblePassword}'
                                )
            for node in GLOBALS.CLUSTER[os.environ["REDUNDANCY"]]:
                passwordChangeStatus += executeSystemCmd(passwordChangeCmd, node, gwpp_info=gwpp_info)
            if passwordChangeStatus:
                log.warning('FAILED TO CHANGE THE PASSWORD')
                # IF LESS THAN 3 days, AUTOMATION MUST ABLE TO CHANGE THE PASSWORD
                if int(days[0]) <= 3:
                    log.abort('ABORTING THE EXECUTION AS CURRENT PASSWORD IS GOING TO EXPIRE IN LESS THAN 3 days')
            else:
                os.environ['gwppPASSWORD'] = nextPossiblePassword
                # DISCONNECT EXISTING CONNECTION [ Connected with old password ]
                log.info('DISCONNECTING EXISTING CONNECTION, AS IT WAS CREATED WITH OLD PASSWORD')
                disconnectSSHConnection(gwpp_info['mgmt-ip-p'], sshUser, sshId)
                log.info(f'RE-TRYING TO CONNECT WITH NEW PASSWORD [{os.environ["gwppPASSWORD"]}] [{gwpp_info["mgmt-ip-p"]}]')
                status = createConnection(gwpp_info['mgmt-ip-p'], sshUser, os.environ['gwppPASSWORD'], sshPort, sshId)
                if os.environ["REDUNDANCY"] == 'True':
                    disconnectSSHConnection(gwpp_info['mgmt-ip-s'], sshUser, sshId)
                    log.info(f'RE-TRYING TO CONNECT WITH NEW PASSWORD [{os.environ["gwppPASSWORD"]}] [{gwpp_info["mgmt-ip-s"]}]')
                    status += createConnection(gwpp_info['mgmt-ip-s'], sshUser, os.environ['gwppPASSWORD'], sshPort, sshId)
                if not status:
                    log.abort('FAILED TO RECONNECT WITH NEW PASSWORD')


def readBuffer(
    node,
    gwpp_info,
    sshUser="admin",
    sshPassword='default',
    sshPort = 22,
    sshIdSuffix=None,
    **kwargs,
    ):
    """
    Method to read the content from an existing ssh connection

    Attributes:
    -----------
    node: active/standby,
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....


    Return:
    -------

        cmdOut:str on successful read
        1 on failure

    """


    sshId = gwpp_info["gwpp_id"]
    host_identifier = "%s_%s" % (sshId, node)
    sshHost = os.getenv(host_identifier)

    # INITIALIZE PASSWORD
    if sshPassword == 'default':
        sshPassword=os.environ['gwppPASSWORD']

    # SPECIFIC SSH CONNECTION
    if sshIdSuffix is not None:
        sshId = sshId + '_' + sshIdSuffix

    sleep(1)
    channelData = readChannel(sshHost, sshUser, sshId)

    # CLEAR PROMPT
    runCmd(
        "",
        sshHost,
        sshUser,
        sshPassword,
        sshPort,
        sshId,
        expect_string=r"[\$#>] $",
        cmdVerify=False,
    )

    return channelData


def executeLinuxCmd(cmd, gwpp_info, read_timeout=240, **kwargs):
    """
    Method to send 'root' level command to gwpp @ port 2024. The expected prompt will always be a linux prompt

    Attributes:
    -----------
    cmd: command to throw on gwpp
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....

    Keyword Argument:
    -----------------

    node: active/standby,

    Return:
    -------

        cmdOut:str on success
        1 on failure

    Usage:
    ------


      executeLinuxCmd('/bin/ls', gwpp_info, node='active' )
      executeLinuxCmd('/bin/ls', gwpp_info, node='standby' )

    """

    # DEFAULT NODE IS 'active'
    node = kwargs["node"] if 'node' in kwargs.keys() else 'active'
    background = kwargs["background"] if "background" in kwargs.keys() else False
    host_identifier = "%s_%s" % (gwpp_info['gwpp_id'], node)
    sshHost = os.getenv(host_identifier)
    sshHost = kwargs['sshHost'] if "sshHost" in kwargs.keys() else sshHost
    # SIM DEFAULs FOR LINUX
    sshPort = 2024
    sshUser = 'root'
    sshPassword = 'password'
    # gwpp IDENTIFIER
    sshId = f'{gwpp_info["gwpp_id"]}_linux'
    sshId = kwargs['sshId'] if "sshId" in kwargs.keys() else sshId

    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sshHost))
    log.trace(f"FOUND SSHID AS {sshId} ON HOST {sshHost}")

    log.info("SENDING COMMAND [%s @ %s_%s_%s_%s]" % (cmd, sshHost, sshId, node, sshUser))
    try:
        return runCmd(
            cmd,
            sshHost,
            sshUser,
            sshPassword,
            sshPort,
            sshId,
            background = background,
            read_timeout=read_timeout,
        )

    except (Exception) as unknown_error:
        log.warning("UNEXPECTED EXCEPTION OCCURED")
        log.warning(unknown_error.args[0])
        return 1


def executeSystemCmd(
    cmd,
    node,
    gwpp_info,
    sshUser="admin",
    sshPassword='default',
    sshPort = 22,
    expect_string=r"[\$#>] $",
    cmdVerify=True,
    connectionLostExpected=False,
    getOutput=False,
    sshIdSuffix=None,
    autoconfirm='False',
    read_timeout=240,
    **kwargs,
):
    """
    Method to send 'system' level command to gwpp. The expected prompt can be change if system command ask for
    Look for Usage for more details

    Attributes:
    -----------
    cmd: command to throw on gwpp
    node: active/standby,
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....
    sshUser : str, Username to login to M/C [ admin/configadmin/superadmin, default: admin ]
    sshPassword: str, Password to use in conjunction with above User
    expect_string: for non-default prompt
    cmdVerify: Boolean, Whether to verify the command output is same as command sent

    Return:
    -------

    0 upon successfull , otherwise 1

    Usage:
    ------

    clear subscriber implementation:

      executeSystemCmd('clear subscriber venb', 'active', gwpp_info, sshUser='admin', sshPassword='admin', expect_string=r'Are You Sure\? \[no,yes\] ')
      executeSystemCmd('yes', 'active', gwpp_info, sshUser='admin', sshPassword='admin')

    system reboot implementation:

      executeSystemCmd('system reboot', 'active', gwpp_info, sshUser='admin', sshPassword='admin', expect_string=r'Do you really want to reboot the system \? \(yes\/no\): ')
      executeSystemCmd('yes', 'active', gwpp_info, sshUser='admin', sshPassword='admin')

    """

    # FAILURE
    error = 0
    # gwpp IDENTIFIER
    sshId = gwpp_info["gwpp_id"]
    host_identifier = f"{sshId}_{node}"
    sshHost = os.getenv(host_identifier) if not kwargs.get('sshHost') else kwargs['sshHost'] 
    log.debug(f"FOUND [ {node} ] gwpp [ sshHost ]")

    # INITIALIZE PASSWORD
    if sshPassword == 'default':
        sshPassword=os.environ['gwppPASSWORD']

    # SPECIFIC SSH CONNECTION
    if sshIdSuffix is not None:
        sshId = sshId + '_' + sshIdSuffix
    cmdOut="" 
    log.info("SENDING COMMAND [%s @ %s_%s_%s_%s]" % (cmd, sshHost, sshId, node, sshUser))
    try:
        cmdOut = runCmd(
            cmd,
            sshHost,
            sshUser,
            sshPassword,
            sshPort,
            sshId,
            expect_string=expect_string,
            cmdVerify=cmdVerify,
            connectionLostExpected=connectionLostExpected,
            autoconfirm=autoconfirm,
            read_timeout=read_timeout,
        )

        # HANDLING OF ?
        if cmd.find('?') != -1:
            return cmdOut

        # VARIOUS ERROR HANDLING
        if cmdOut == False:
            log.warning(f"{cmd} OUTPUT IS UNEXPECTED")

        # VARIOUS ERROR HANDLING
        for errorPattern in ERROR_PATTERNS:
            match = errorPattern.search(cmdOut)
            if match:
                log.warning(f"DETECTED [{match.group()}] WHILE SENDING COMMAND") 
                error = 1
                break

    except (Exception) as unknown_error:
        log.warning("UNEXPECTED EXCEPTION OCCURED")
        log.warning(unknown_error.args[0])
        error = 1
        cmdOut="" 

    finally:
        if not error:
            # RECORD FOR AUDIT-TRAIL
            if os.environ["RECORD_COMMANDS_FOR_AUDIT_TRAIL"] == 'True' and cmd != '':
                AUDIT_TRAIL_COMMAND.append(f'{sshUser} : {cmd}')
        if getOutput:
            return (error, cmdOut)
        return error

def executeMultipleSystemCmds(cmds,
                            node,
                            gwpp_info,
                            sshUser="admin",
                            sshPassword='default',
                            sshPort = 22,
                            expect_string=r"[\$#>] $",
                            cmdVerify=True,
                            connectionLostExpected=False,
                            getOutput=False,
                            sshIdSuffix=None,
                            autoconfirm='False',
                            **kwargs,
                            ):
    """
    Method to send multiple 'system' level commands to gwpp at once without waiting for the prompt.
    Look for Usage for more details

    Attributes:
    -----------
    cmds: commands to throw on gwpp
    node: active/standby,
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....
    sshUser : str, Username to login to M/C [ admin/configadmin/superadmin, default: admin ]
    sshPassword: str, Password to use in conjunction with above User

    Return:
    -------
    None

    Usage:
    ------
    cmd = "clear venb gtpu statistics access"
    cmdlist = ""
    for cmdIndex in range(500):
        cmdlist += cmd + '\n'
    executeMultipleSystemCmds(cmd=cmdlist, node=node,
                         gwpp_info=self.gwpp1.venb.gwpp_info)
    """

    # gwpp IDENTIFIER
    sshId = gwpp_info["gwpp_id"]
    host_identifier = "%s_%s" % (sshId, node)
    sshHost = os.getenv(host_identifier)
    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sshHost))

    # INITIALIZE PASSWORD
    if sshPassword == 'default':
        sshPassword=os.environ['gwppPASSWORD']

    # SPECIFIC SSH CONNECTION
    if sshIdSuffix is not None:
        sshId = sshId + '_' + sshIdSuffix

    sendCmds(cmds,
             sshHost,
             sshUser,
             sshPassword,
             sshPort,
             sshId,
             expect_string=expect_string,
             cmdVerify=cmdVerify,
             connectionLostExpected=connectionLostExpected,
             autoconfirm=autoconfirm,
    )
    
    return 

def stopMultipleSystemCmds(node,
                            gwpp_info,
                            sshUser="admin",
                            sshPassword='default',
                            sshPort = 22,
                            connectionLostExpected=False,
                            sshIdSuffix=None,
                            **kwargs,
                        ):
    sshId = gwpp_info["gwpp_id"]
    host_identifier = "%s_%s" % (sshId, node)
    sshHost = os.getenv(host_identifier)
    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sshHost))

    # INITIALIZE PASSWORD
    if sshPassword == 'default':
        sshPassword=os.environ['gwppPASSWORD']

    # SPECIFIC SSH CONNECTION
    if sshIdSuffix is not None:
        sshId = sshId + '_' + sshIdSuffix
    disconnectSSHConnection(sshHost, sshUser, sshId)
    return


def executeShowCmd(
    cmd,
    node,
    gwpp_info,
    filter_option="notab",
    sshUser="admin",
    sshPassword='default',
    sshPort = 22,
    sshIdSuffix=None,
    read_timeout=240,
    **kwargs,
    ):

    """
    Method to send 'show' command to gwpp. Show commands usually return the command output in form of either column or tabular format
    By default each command will be appended with '| notab'.
    It is recommended to run all 'show running configuration' command with filer_option='nomore' to avoid any pagination

    Attributes:
    -----------
    cmd: command to throw on gwpp
    node: active/standby,
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....
    filter_option: any supported format by gwpp after a | [ i.e. xml, json, notab, any key, etc. default: notab]
    sshUser : str, Username to login to M/C [ admin/configadmin/superadmin, default: admin ]
    sshPassword: str, Password to use in conjunction with above User

    Return:
    -------

    cmdOut upon successful , otherwise 1

    Usage:
    ------

    def checkS1apStatistics(self, attributes, parameter, context='core', instance='venbautomation1', node="active"):
                 cmd = 'show venb s1ap statistics %s %s | include %s' % (context, instance, parameter)
                 cmdOut = executeShowCmd(cmd, node, self.gwpp_info)

    def getRunningConfig(self, profileName, node='active'):
                 cmd = 'show running-config profiles venb-profile %s' % (profileName)
                 cmdOut = executeShowCmd(cmd, node, self.gwpp_info, filter_option='nomore')

    """

    # gwpp ID: gwpp1, gwpp2 etc
    sshId = gwpp_info["gwpp_id"]
    # gwpp IDENTIFIER
    host_identifier = "%s_%s" % (sshId, node)
    sshHost = os.getenv(host_identifier)
    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sshHost))
    # cmd
    if filter_option is not None:
        cmd += r" | " + filter_option
    cmdOut = ''

    # INITIALIZE PASSWORD
    if sshPassword == 'default':
        sshPassword=os.environ['gwppPASSWORD']

    # SPECIFIC SSH CONNECTION
    if sshIdSuffix is not None:
        sshId = sshId + '_' + sshIdSuffix

    log.info("SENDING COMMAND [%s @ %s_%s_%s_%s]" % (cmd, sshHost, sshId, node, sshUser))
    try:
        cmdOut = runCmd(cmd, sshHost, sshUser, sshPassword, sshPort, sshId, read_timeout=read_timeout)

        # RECORD FOR AUDIT-TRAIL
        if os.environ["RECORD_COMMANDS_FOR_AUDIT_TRAIL"] == 'True':
            AUDIT_TRAIL_COMMAND.append(f'{sshUser} : {cmd}')

        # VARIOUS ERROR HANDLING
        for errorPattern in ERROR_PATTERNS:
            match = errorPattern.search(cmdOut)
            if match:
                log.warning(f"DETECTED [{match.group()}] WHILE SENDING COMMAND") 
                break

    except (Exception) as unknown_error:
        log.warning("UNEXPECTED EXCEPTION OCCURED")
        log.warning(unknown_error.args[0])
        cmdOut = ''

    finally:
        return cmdOut


def executeConfigCmd(
    cmdList,
    gwpp_info,
    sshUser="admin",
    sshPassword='default',
    sshIdSuffix=None,
    read_timeout=240,
    **kwargs,
    ):
    """
    Method to send 'config' command to 'active' gwpp back-to-back. Standby gwpp is in 'read-only' mode.
    The method takes care to enter to config mode of gwpp, and at last make sure it always comes-out of config mode

    Attributes:
    -----------
    cmdList: list of commands to configure on gwpp
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....
    sshUser : str, Username to login to M/C [ admin/configadmin/superadmin, default: admin ]
    sshPassword: str, Password to use in conjunction with above User

    Return:
    -------

    0 upon successfull , otherwise 1

    Usage:
    ------

         def create(self, zoneName, mcc, mnc, tac, eaid):
                 cmdList = []
                 cmdList.append('zone')
                 cmdList.append('venb-zone %s' % zoneName)
                 cmdList.append('plmn mcc %s mnc %s home true' % (mcc, mnc))
                 cmdList.append('tracking-area-code %s' % (tac))
                 cmdList.append('emergency-area-id %s' % (eaid))

                 executeConfigCmd(cmdList, self.gwpp_info)

    """

    # FAILURE
    error = 0
    # gwpp DEFAUL PORT
    sshPort = 22
    # gwpp ID: gwpp1, gwpp2 etc
    sshId = gwpp_info["gwpp_id"]
    # CONFIGURATION ALWAYS ON 'active'
    node = "active"
    # 'active' gwpp IDENTIFIER
    host_identifier = "%s_%s" % (sshId, node)
    sshHost = os.getenv(host_identifier)
    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sshHost))

    # INITIALIZE PASSWORD
    if sshPassword == 'default':
        sshPassword=os.environ['gwppPASSWORD']

    # SPECIFIC SSH CONNECTION
    if sshIdSuffix is not None:
        sshId = sshId + '_' + sshIdSuffix

    # CONFIGURE
    # GO TO CONFIG MODE
    cmdList.insert(0, 'config')
    # MAKE SURE TO EXIT FROM CONFIG MODE
    cmdList.append('end')

    for cmd in cmdList:
        log.info("SENDING COMMAND [%s @ %s_%s_%s_%s]" % (cmd, sshHost, sshId, node, sshUser))
        
        try:
            cmdOut = runCmd(cmd, sshHost, sshUser, sshPassword, sshPort, sshId,
                            expect_string=r"([\$#>] $)|(Proceed\?\s*\[yes,no\] $)|(Overwrite\?\s*\[yes,no\] $)", autoconfirm='yes',
                            read_timeout=read_timeout)

            # VARIOUS ERROR HANDLING
            for errorPattern in ERROR_PATTERNS:
                match = errorPattern.search(cmdOut)
                if match:
                    log.warning(f"DETECTED [{cmdOut}] WHILE SENDING COMMAND") 
                    error = 1
                    break

            if error:
                # SEND 'end' TO BRING gwpp TO MAIN PROMPT
                cmdOut = runCmd('end', sshHost, sshUser, sshPassword, sshPort, sshId)
                break

            if os.environ["RECORD_COMMANDS_FOR_AUDIT_TRAIL"] == 'True' and cmd != '':
                AUDIT_TRAIL_COMMAND.append(f'{sshUser} : {cmd}')

        except (Exception) as unknown_error:
            log.warning("UNEXPECTED EXCEPTION OCCURED")
            log.warning(unknown_error.args[0])
            error = 1

    return error


def transferFile(localFile, remoteFile, localPath, remotePath, node, gwpp_info, sshUser="root", sshPassword="password", direction="put", disable_md5=False, **kwargs):
    """
    Method to transfer files to gwpp or from gwpp.

    Attributes:
    -----------
    localFile: file to transfer
    remoteFile: file to receive
    localPath: file local path
    remotePath: file remote path
    node: active/standby,
    gwpp_info: Used to derive IP address of host [ active/standby ] with hostId : i.e. gwpp1/gwpp2/gwpp3....
    sshUser : str, Username to login to M/C [ admin/configadmin/superadmin, default: admin ]
    sshPassword: str, Password to use in conjunction with above User
    direction: str, file transfer direction

    Return:
    -------

    N/A

    Usage:
    ------

    tf(localFile, remoteFile, localPath, remotePath, sshHost, sshUser, sshPassword, sshPort, sshId, direction=direction)

    """

    # gwpp DEFAUL PORT
    sshPort = 2024
    # gwpp ID: gwpp1, gwpp2 etc
    sshId = gwpp_info["gwpp_id"]
    # gwpp IDENTIFIER
    host_identifier = "%s_%s" % (sshId, node)
    sshHost = os.getenv(host_identifier)
    sshHost = kwargs['sshHost'] if "sshHost" in kwargs.keys() else sshHost
    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sshHost))

    # OVERWRITE gwpp IDENTIFIER
    sshId = kwargs['sshId'] if "sshId" in kwargs.keys() else sshId

    return tf(localFile, remoteFile, localPath, remotePath, sshHost, sshUser, sshPassword, sshPort, sshId, direction=direction, disable_md5=disable_md5)


def executeSftpCmd(
        cmd=None,
        localFile=None,
        remoteFile=None,
        localPath=None,
        remotePath=None,
        node="active",
        gwpp_info=None,
        sftpUser="pws",
        sftpPassword="pwsunisftp",
        sftpPort=2024,
        operation="put", **kwargs
    ):
    """
    Method to perform 'sftp' login level command to gwpp @ port 2024.

    Attributes:
    -----------
    localFile: str, The name of local file [ irrespective exists or not, depending on direction]
    remoteFile: str, The name of remote file [ irrespective exists or not, depending on direction]
    localPath: str, The path of local file [ should exists ]
    remotePath: str, The name of remote file [ should exists ]
    sftpHost : str, IPv4 Address, should be reachable from AH
    sftpUser : str, Username to login to M/C
    sftpPassword: str, Password to use in conjunction with above User
    sftpPort: int, SSH Port running on Host
    sftpId: str, A unique user-defined string, identifier for the SSH Connection
    operation: put/get,
                put -> File will be transfer from local host to remote host [ sftpHost ]
                get -> File will be downloaded from remote host [ sftpHost ] to local host
        file existence will be checked on local host or remote host depends on direction

    Keyword Argument:
    -----------------
    sftpId: active/standby,

    Return:
    -------

        cmdOut:str on success
        1 on failure

    Usage:
    ------

      executeSftpCmd(localFile, remoteFile, localPath, remotePath, sftpHost, sftpUser, sftpPassword, sftpPort, sftpId, operation='get')

    """
    # DEFAULT NODE IS 'active'
    host_identifier = "%s_%s" % (gwpp_info['gwpp_id'], node)
    sftpHost = os.getenv(host_identifier)
    sftpHost = kwargs['sftpHost'] if "sftpHost" in kwargs.keys() else sftpHost
    # gwpp IDENTIFIER
    sftpId = f'{gwpp_info["gwpp_id"]}_sftp'
    sftpId = kwargs['sftpId'] if "sftpId" in kwargs.keys() else sftpId

    log.debug("FOUND [ %s ] gwpp [ %s ]" % (node, sftpHost))
    log.trace(f"FOUND SFTPID AS {sftpId} ON HOST {sftpHost}")

    log.info(f"SENDING SFTP OPERATION {operation} NODE [{node}]")

    try:
        return sftpRunCmd(
            sftpHost,
            sftpUser,
            sftpPassword,
            sftpPort,
            sftpId,
            cmd=cmd,
            localFile=localFile,
            remoteFile=remoteFile,
            localPath=localPath,
            remotePath=remotePath,
            operation=operation,
        )

    except (Exception) as unknown_error:
        log.warning("UNEXPECTED EXCEPTION OCCURED")
        log.warning(unknown_error.args[0])
        return (1, 1)

