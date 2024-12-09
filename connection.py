import socket
import os
import re
import time
import netmiko
import paramiko

from netmiko import file_transfer
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
from benedict import benedict
from copy import deepcopy
from LOGGER import log

SSH_CONNECTION = benedict()
SFTP_CONNECTION = benedict()

# NETMIKO INTERNAL VARIABLES TO COMPUTE read_timeout OF A CHANNEL AFTER SENDING A COMMAND
NETMIKO_LOOP_DELAY = 0.2
NETMIKO_DELAY_FACTOR = 2
NETMIKO_MAX_LOOPS = 600

#Enforcing Netmiko module not to print it's internal debug level messages unless TRACE level is enabled
log.setLogLevel('INFO')
loglevel = os.environ['CONSOLE_LOG_LEVEL']

if(loglevel == 'TRACE'): 
    log.setLogLevel('TRACE')
    

def __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId, file_mode="write"):
    """
    An internal method to establish SSH Connection with 'Linux OS' type devices using Netmiko Library
    Not suppose to use it outside of this module

    Attributes:
    -----------
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshPassword: str, Password to use in conjunction with above User
    sshPort: int, SSH Port running on Host
    sshId: str, A unique user-defined string, identifier for the SSH Connection
    file_mode: write/append, Based on input the file /tmp/ssh_<ip>_<user>_<id> will be rewrite or appended

    Return:
    -------

    True upon successfull ssh connection, otherwise False

    Usage:
    ------

    __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId)

    """

    # INITILIZE DEFAULT VARIABLEs
    sshConnectionName = "{}_{}_{}".format(sshHost, sshUser, sshId)
    sshSessionLog = "/tmp/ssh_{}.txt".format(sshConnectionName)
    sshLoginTimeout = 100
    sshAuthTimeout = 60
    sshOSType = "linux"
    sshConnection = ""
    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    status = True

    # CHANGE OWNERSHIP & DELETE CONTENT OF THE FILE
    if file_mode == "write":
        try:
            os.system(f"touch {sshSessionLog}")
            os.system(f"echo > {sshSessionLog}")
            os.system(f"chmod 0777 {sshSessionLog}")
        except:
            log.trace(f"UNABLE TO CHANGE FILE PERMISSION {sshSessionLog}")

    log.trace(f"SSH - HOST [{sshHost}] USER [{sshUser}] PASSWORD [{sshPassword}] PORT [{sshPort}] ID [{sshId}]")

    # CONSTRUCT CONNECTION PARAMETER
    remote_device = {
                        "device_type": sshOSType,
                        "host": sshHost,
                        "username": sshUser,
                        "password": sshPassword,
                        "port": sshPort,
                        "timeout": sshLoginTimeout,
                        "auth_timeout": sshAuthTimeout,
                        "session_log": sshSessionLog,
                        "session_log_record_writes": "false",
                        "session_log_file_mode": file_mode,
                        "verbose": "False",
                        "encoding": "utf8"
    }

    # INSTANTIATE SSH CONNECTION
    try:
        sshConnection = netmiko.ConnectHandler(**remote_device)
        SSH_CONNECTION.setdefault(sshHostUnderScore, {}).setdefault(sshUser, {})[sshId] = sshConnection
        log.info(f"SSH CONNECTION TO HOST [{sshHost}@{sshPort}] CREATED SUCCESSFULLY")
        log.info(f"SSH LOG FILE: [{sshSessionLog}]")
    except NetMikoTimeoutException as timeout_error:
        log.warning(f"COULD NOT CONNECT TO HOST [{sshHost}] IN TIME [{sshLoginTimeout}]")
        log.warning(timeout_error.args[0])
        status = False
    except NetMikoAuthenticationException as auth_error:
        log.warning(f"COULD NOT CONNECT TO HOST [{sshHost}] WITH USER/PASSWD [{sshUser}/{sshPassword}]")
        log.warning(auth_error.args[0])
        status = False
    except (EOFError, SSHException) as unknown_error:
        log.warning("COULD NOT CONNECT TO HOST [{}]".format(sshHost))
        log.warning(unknown_error.args[0])
        status = False

    return status


def disconnectSSHConnection(sshHost, sshUser, sshId):
    """
    An internal method to disconnect/terminate SSH Connection created by __createSSHConnection

    Attributes:
    -----------
    sshHost : str, IPv4 Address, from which ssh connection required to terminate
    sshUser : str, Username to identify the SSH connection
    sshId: str, A unique user-defined string, to identify the SSH Connection

    Return:
    -------

    None, but delete the dictionary key for sshHost, sshUser, and sshId upon termination

    Usage:
    ------

    disconnectSSHConnection(sshHost, sshUser, sshId)

    """

    log.info("TERMINATING ssh CONNECTION TO HOST [{}_{}]".format(sshHost, sshId))
    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    SSH_CONNECTION[sshHostUnderScore][sshUser][sshId].disconnect()
    del SSH_CONNECTION[sshHostUnderScore][sshUser][sshId]

def getSSHConnection(sshHost, sshUser, sshId):
    """
    An internal method to return existing SSH Connection created by __createSSHConnection

    Attributes:
    -----------
    sshHost : str, IPv4 Address, from which ssh connection required to terminate
    sshUser : str, Username to identify the SSH connection
    sshId: str, A unique user-defined string, to identify the SSH Connection

    Return:
    -------

    Netmiko ssh callable object

    Usage:
    ------

    getSSHConnection(sshHost, sshUser, sshId)

    """

    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    return SSH_CONNECTION[sshHostUnderScore][sshUser][sshId].disconnect()


def disconnectAll(sshHost):
    """
    An method to disconnect/terminate all SSH Connection created by __createSSHConnection for specefic host 
    Should call at project level to disconnect with all machine gracefully before completing the execution

    Attributes:
    -----------
    sshHost, Just look at SSH_CONNECTION dictionary and disconnect from each one-by-one

    Return:
    -------

    None, but delete the dictionary key for sshHost, sshUser, and sshId upon termination

    Usage:
    ------

    disconnectAll(sshHost)

    """
    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    # SSH_CONNECTION
    for sshUser in SSH_CONNECTION[sshHostUnderScore].copy().keys():
        for sshId in SSH_CONNECTION[sshHostUnderScore][sshUser].copy().keys():
            log.info(f'Deleting ssh connection for sshUser:{sshUser} sshId:{sshId} sshHost:{sshHost}')
            SSH_CONNECTION[sshHostUnderScore][sshUser][sshId].disconnect()
            del SSH_CONNECTION[sshHostUnderScore][sshUser][sshId]
    # SFTP_CONNECTION
    if sshHostUnderScore in SFTP_CONNECTION:
        for sftpUser in SFTP_CONNECTION[sshHostUnderScore].copy().keys():
            for sftpId in SFTP_CONNECTION[sshHostUnderScore][sftpUser].copy().keys():
                log.info(f'Deleting sftp connection for sftpUser:{sftpUser} sftpId:{sftpId}')
                SFTP_CONNECTION[sshHostUnderScore][sftpUser][sftpId].close()
                del SFTP_CONNECTION[sshHostUnderScore][sftpUser][sftpId]


def transferFile(
    localFile,
    remoteFile,
    localPath,
    remotePath,
    sshHost,
    sshUser,
    sshPassword,
    sshPort,
    sshId,
    direction="put",
    disable_md5=False,
    retry=1,
):
    """
    This help in transferring the files from/to local [AH] m/c to/from other m/c using Netmiko Library

    Attributes:
    -----------
    localFile: str, The name of local file [ irrespective exists or not, depending on direction]
    remoteFile: str, The name of remote file [ irrespective exists or not, depending on direction]
    localPath: str, The path of local file [ should exists ]
    remotePath: str, The name of remote file [ should exists ]
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshPassword: str, Password to use in conjunction with above User
    sshPort: int, SSH Port running on Host
    sshId: str, A unique user-defined string, identifier for the SSH Connection
    direction: put/get,
                put -> File will be transfer from local host to remote host [ sshHost ]
                get -> File will be downloaded from remote host [ sshHost ] to local host
        file existence will be checked on local host or remote host depends on direction

    Return:
    -------

    True upon successfull file transfer, otherwise False

    Usage:
    ------

    transferFile(localFile, remoteFile, localPath, remotePath, sshHost, sshUser, sshPassword, sshPort, sshId, direction)

    """

    log.debug(f"LOCAL FILE [ {localFile} ]")
    log.debug(f"LOCAL PATH [ {localPath} ]")
    log.debug(f"REMOTE FILE [ {remoteFile} ]")
    log.debug(f"REMOTE PATH [ {remotePath} ]")
    log.debug(f"M/C: SSH-HOST [ {sshHost} ]")
    log.debug(f"M/C: SSH-USER [ {sshUser} ]")
    log.debug(f"M/C: SSH-PASSWORD [ {sshPassword} ]")
    log.debug(f"M/C: SSH-PORT [ {sshPort} ]")
    log.debug(f"M/C: SSH-ID [ {sshId} ]")
    log.debug(f"DIRECTION [ {direction} ]")

    status = True
    if direction == "put":
        # MAKE SURE FILE DOESNOT EXISTS @ REMOTE M/C
        cmd = f"/bin/rm -f {remotePath}/{remoteFile}"
        log.info(f"DELETING CONFIG FILE [ {cmd} ]")
        runCmd(cmd, sshHost, sshUser, sshPassword, sshPort, sshId)
        source_file = localFile
        dest_file = remoteFile
        log.info(f"TRANSFERRING FILE [LOCALHOST: {localPath}/{source_file}] TO FILE [REMOTEHOST: {remotePath}/{dest_file}]")
    elif direction == "get":
        d = "FROM"
        source_file = remoteFile
        dest_file = localFile
        log.info(f"TRANSFERRING FILE [REMOTEHOST: {remotePath}/{source_file}] TO FILE [LOCALHOST: {localPath}/{dest_file}]")
    else:
        log.error("UNSUPPORTED DIRECTION, MUST BE ONE OF [ get or put ]")
        return False

    # GO TO CONFIG DIRECTORY
    originalDir = os.getcwd()
    try:
        os.chdir(localPath)
    except (FileNotFoundError) as fError:
        log.warning(fError)
        log.error(f"DIRECTORY [{localPath}] NOT FOUND")
        return False
    except Exception as err:
        log.warning(err)
        statusOut = str(err)
        return False

    # CHECK AND CREATE SSH CONNECTION
    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    log.trace(f"UNDERSCORE ssh-host [ {sshHostUnderScore} ]")
    keyChain = f"{sshHostUnderScore}.{sshUser}.{sshId}"
    log.trace("KEY CHAIN [ %s ]" % keyChain)
    log.trace(SSH_CONNECTION)
    if keyChain not in SSH_CONNECTION:
        log.trace("DID NOT FIND CONNECTION, CREATING A NEW ONE")
        __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId)

    try:
        transferStatus = file_transfer(
                                        SSH_CONNECTION[sshHostUnderScore][sshUser][sshId],
                                        source_file=source_file,
                                        dest_file=dest_file,
                                        direction=direction,
                                        file_system=remotePath,
                                        overwrite_file=True,
                                        disable_md5=disable_md5,
        )
    except (IOError) as ioError:
        log.warning(ioError)
        status = False
    except Exception as err:
        log.warning(err)
        statusOut = str(err)
        status = False

    # GO BACK TO ORIGINAL DIRECTORY
    os.chdir(originalDir)

    if status:
        log.info(transferStatus)
        if transferStatus["file_exists"] != True and direction == "put":
            log.error(f"FILE [{localPath}/{localFile}] DOES NOT EXISTS ON LOCAL MACHINE")
            status = False
        elif transferStatus["file_exists"] != True and direction == "get":
            log.error(f"FILE [{remotePath}/{remoteFile}] DOESN'T EXISTS ON REMOTE MACHINE")
            status = False
        elif transferStatus["file_transferred"] != True:
            log.error("FILE COULD NOT TRANSFERRED")
            status = False
        elif transferStatus["file_transferred"] == True and disable_md5 == True:
            log.debug("FILE TRANSFERRED, BUT MD5 CHECKSUM DISABLED")
        elif transferStatus["file_verified"] != True:
            log.error("FILE TRANSFERRED, BUT CHECKSUM DID NOT MATCH")
            status = False

    # RETRY [ MAX 3 TIMES ] TO TRANSFER THE FILE, IN CASE TRANSFERRING THE FILE FAILED EARLIER
    if not status and retry <= 3:
        log.sleep(10, f"FAILED TO TRANSFER FILE, RETRYING [{retry}]")
        retry += 1
        transferFile(
                        localFile,
                        remoteFile,
                        localPath,
                        remotePath,
                        sshHost,
                        sshUser,
                        sshPassword,
                        sshPort,
                        sshId,
                        direction,
                        disable_md5,
                        retry=retry,
        )

    return status


def clearBuffer(sshHost, sshUser, sshId):
    """
    A common method to to clear SSH Channel

    Attributes:
    -----------
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshId: str, A unique user-defined string, identifier for the SSH Connection

    Return:
    -------

    None

    Usage:
    ------

    clearBuffer(sshHost, sshUser, sshId)

    """

    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    log.trace(f"UNDERSCORE ssh-host [ {sshHostUnderScore} ]")
    keyChain = f"{sshHostUnderScore}.{sshUser}.{sshId}"
    log.trace(f"KEY CHAIN [ {keyChain} ]")
    log.trace(SSH_CONNECTION)
    connectionObject = SSH_CONNECTION[sshHostUnderScore][sshUser][sshId] 
    connectionObject.clear_buffer()
 

def readChannel(sshHost, sshUser, sshId):
    """
    A common method to to read all data from existing SSH Channel

    Attributes:
    -----------
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshId: str, A unique user-defined string, identifier for the SSH Connection

    Return:
    -------

    None

    Usage:
    ------

    readChannel(sshHost, sshUser, sshId)

    """

    log.info(f'READING CHANNEL FOR [{sshHost}:{sshUser}:{sshId}]')
    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    log.trace(f"UNDERSCORE ssh-host [ {sshHostUnderScore} ]")
    keyChain = f"{sshHostUnderScore}.{sshUser}.{sshId}"
    log.trace(f"KEY CHAIN [ {keyChain} ]")
    log.trace(SSH_CONNECTION)
    connectionObject = SSH_CONNECTION[sshHostUnderScore][sshUser][sshId] 
    return(connectionObject.read_channel())
 

def runCmd(
    cmd,
    sshHost,
    sshUser,
    sshPassword,
    sshPort,
    sshId,
    expect_string=r"[\$#>] $",
    background=False,
    retry=True,
    cmdVerify=True,
    connectionLostExpected=False,
    retryUntilSuccess=False,
    autoconfirm='False',
    file_mode='write',
    read_timeout=240,
):
    """
    A common method to throw a command on ssh connection and retrieve the ouput and forward back to caller
    The connection is not necessarily to be exists. In case ssh connection to the remote host does not exists, this will try
    to create connection first, and later throw the command

    Attributes:
    -----------
    cmd: str, Command to be sent on remote host
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshPassword: str, Password to use in conjunction with above User
    sshPort: int, SSH Port running on Host
    sshId: str, A unique user-defined string, identifier for the SSH Connection
    expect_string: For non-default prompt, the execpted string can be passed [ e.x. 'clear subscriber venb', request for no,yes ]
    background: If command needs to run in background, like [ iperf ]
    retry: Yet to implement, On implementing, if an error noticed while throwing command, a new ssh connection will try to open after
            100 seconds, and rethrow the command

    Return:
    -------

    Command Output in form of 'string', along with pid [ if background is True ], otherwise False

    Usage:
    ------

    runCmd(cmd, sshHost, sshUser, sshPassword, sshPort, sshId, expect_string=r'[\$%#>] $', background=False, retry=False,cmdVerify=True):

    """

    log.trace(f"BACKGROUND IS {background}")
    if background:
        cmd += " &"

    # DEFAULT 'max_loops' & 'delay_factor' FOR read_timeout = 240 seconds
    max_loops = NETMIKO_MAX_LOOPS
    delay_factor = NETMIKO_DELAY_FACTOR
    # COMPUTE max_loop
    if read_timeout != 240:
        max_loops = int(( read_timeout / delay_factor ) / NETMIKO_LOOP_DELAY)
    log.trace(f'MAX_LOOPS [{max_loops}] : DELAY_FACTOR [{delay_factor}] : CHANNEL_READ_TIMEOUT [{read_timeout}]')

    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    log.trace(f"UNDERSCORE ssh-host [ {sshHostUnderScore} ]")
    keyChain = f"{sshHostUnderScore}.{sshUser}.{sshId}"
    log.trace(f"KEY CHAIN [ {keyChain} ]")
    log.trace(SSH_CONNECTION)
    if keyChain not in SSH_CONNECTION:
        log.trace("DID NOT FIND CONNECTION, CREATING A NEW ONE")
        __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId, file_mode)

    # SSH OBJECT
    connectionObject = SSH_CONNECTION[sshHostUnderScore][sshUser][sshId] 

    # HANDLING OF ?
    # MANIPULATE expect_string IF COMMAND IS HAVING ?
    if cmd.find(' ?') != -1:
        expect_string = cmd.split('?')[0].strip()
        cmdVerify = False
        # WRITE COMMAND
        connectionObject.write_channel(cmd)
        log.sleep(2,"Before reading the Data")
        cmdOut = connectionObject.read_until_prompt_or_pattern(pattern=expect_string)
        log.info("SENDING ctrl+c")
        connectionObject.write_channel('\x03')
        clearBuffer(sshHost, sshUser, sshId)
        return cmdOut

    try:
        log.logCommand(f'[{sshHost:15}] {cmd}'); # LOG EVERY COMMAND TO A SEPERATE LOG FILE .cli
        log.trace(f"EXPECTING STRING [ {expect_string} ], CMD_VERIFY [{cmdVerify}], AUTOCONFIRM [{autoconfirm}]")
        # REMOVE ANY OUTPUT FROM PREVIOUS COMMAND BEFORE SENDING COMMAND
        clearBuffer(sshHost, sshUser, sshId)
        cmdOut = connectionObject.send_command(cmd, expect_string=expect_string, cmd_verify=cmdVerify, delay_factor=delay_factor, max_loops=max_loops)
        log.trace("COMMAND OUTPUT: \n {}".format(cmdOut))

        # IF COMMAND IS REQUIRED 'yes/no' TO PROCEED FURTHER
        if cmdOut.find('yes') != -1 and autoconfirm is not 'False':
            log.info(f"DETECTED [{cmdOut}], SENDING [{autoconfirm}]")
            cmdOut = connectionObject.send_command(autoconfirm, expect_string=r"[\$#>] $", cmd_verify=False, delay_factor=delay_factor, max_loops=max_loops)

        # RECORD PID, IF PROCESS IS IN BACKGROUND
        if background:
            pid = runCmd("echo $!", sshHost, sshUser, sshPassword, sshPort, sshId)
            log.info(f"COMMAND PID IS {pid}")
            return cmdOut, pid

        # REMOVE CONNECTION HANDLER, IF CONNECTION LOST IS EXPECTED, i.e. 'system reboot'
        if connectionLostExpected == True:
            log.info(f'EXPECTING CONNECTION TO BE LOST, DELETING ALL EXISTING CONNECTION ON HOST [{sshHost}]')
            disconnectAll(sshHost)
        if connectionLostExpected == 'session-only':
            log.info('EXPECTING CONNECTION TO BE LOST, DELETING EXISTING CONNECTION')
            disconnectSSHConnection(sshHost, sshUser, sshId)

        return cmdOut

    except (socket.error, EOFError, SSHException) as E:
        log.warning(E.args[0])
        try:
            cmdOut = connectionObject.send_command("", expect_string=r"[\$#>] $")
            return False
        except (socket.error, EOFError, SSHException) as E:
            log.warning(f"CONNECTION TO HOST [{ sshHost }] SEEMS TO BE LOST, TRYING TO RESTORE")
        del connectionObject
        if connectionLostExpected == True:
            log.info("CONNECTION LOST. EXPECTED BEHAVIOUR. WAITING FOR FEW SECONDS FOR MACHINE TO BE UP BEFORE CONNECTING AGAIN")
            return True
        if retryUntilSuccess == True:
            status = False
            while status != True:
                status = __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId, file_mode="append")
                retry = False
                return True
        else:
            log.sleep(2, f'NEW CONNECTION ESTABLISHED WITH {sshId}, GIVING A SETTLING TIME FOR 2 SECONDS')
            reconSshId = __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId, file_mode="append")
            log.info("CALLING THE FUNCTION 'runCmd' WITH SAME ARGUMENT LISTS")
            if all([reconSshId, retry]):
                return runCmd(cmd, sshHost, sshUser, sshPassword, sshPort, sshId, expect_string=expect_string, background=background, retry=False, cmdVerify=cmdVerify, connectionLostExpected=connectionLostExpected, retryUntilSuccess=False, autoconfirm=autoconfirm, file_mode="append")

        return False


def createConnection(sshHost, sshUser, sshPassword, sshPort, sshId, expect_string=r"[\$%#>] $"):
    """
    Method to create a new connection, and return a netmiko Object to the caller

    Attributes:
    -----------
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshPassword: str, Password to use in conjunction with above User
    sshPort: int, SSH Port running on Host
    sshId: str, A unique user-defined string, identifier for the SSH Connection
    expect_string: For non-default prompt, the execpted string can be passed [ e.x. 'clear subscriber venb', request for no,yes ]

    Return:
    -------

    Netmiko ssh object

    Usage:
    ------

    createConnection(sshHost, sshUser, sshPassword, sshPort, sshId, expect_string=r'[\$%#>] $')

    """

    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    log.trace(f"UNDERSCORE ssh-host [ {sshHostUnderScore} ]")
    keyChain = f"{sshHostUnderScore}.{sshUser}.{sshId}"
    log.trace(f"KEY CHAIN [ {keyChain} ]")
    log.trace(SSH_CONNECTION)
    if keyChain not in SSH_CONNECTION:
        log.trace("DID NOT FIND CONNECTION, CREATING A NEW ONE")
        return __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId)

def sendCmds(
        cmds,
        sshHost,
        sshUser,
        sshPassword,
        sshPort,
        sshId,
        expect_string=r"[\$#>] $",
        background=False,
        retry=True,
        cmdVerify=True,
        connectionLostExpected=False,
        retryUntilSuccess=False,
        autoconfirm='False',
        file_mode='write',
        ):
    """
    A common method to throw multiple commands on ssh connection without retrieving the ouput
    The connection is not necessarily to be exists. In case ssh connection to the remote host does not exists, this will try
    to create connection first, and later throw the command

    Attributes:
    -----------
    cmd: str, Command to be sent on remote host
    sshHost : str, IPv4 Address, should be reachable from AH
    sshUser : str, Username to login to M/C
    sshPassword: str, Password to use in conjunction with above User
    sshPort: int, SSH Port running on Host
    sshId: str, A unique user-defined string, identifier for the SSH Connection
    expect_string: For non-default prompt, the execpted string can be passed [ e.x. 'clear subscriber venb', request for no,yes ]
    background: If command needs to run in background, like [ iperf ]
    retry: Yet to implement, On implementing, if an error noticed while throwing command, a new ssh connection will try to open after
            100 seconds, and rethrow the command

    Return:
    -------

    None
    
    Usage:
    ------

    sendCmds(cmd, sshHost, sshUser, sshPassword, sshPort, sshId, expect_string=r'[\$%#>] $', background=False, retry=False,cmdVerify=True):

    """
    sshHostUnderScore = re.sub(r"\.", "_", sshHost)
    log.trace(f"UNDERSCORE ssh-host [ {sshHostUnderScore} ]")
    keyChain = f"{sshHostUnderScore}.{sshUser}.{sshId}"
    log.trace(f"KEY CHAIN [ {keyChain} ]")
    log.trace(SSH_CONNECTION)
    if keyChain not in SSH_CONNECTION:
        log.trace("DID NOT FIND CONNECTION, CREATING A NEW ONE")
        __createSSHConnection(sshHost, sshUser, sshPassword, sshPort, sshId, file_mode)

    # SSH OBJECT
    connectionObject = SSH_CONNECTION[sshHostUnderScore][sshUser][sshId] 

    # WRITE COMMANDS
    connectionObject.write_channel(cmds)
    clearBuffer(sshHost, sshUser, sshId)
    
    return
    
    
def readFileBuffer(sshId, sshHost, sshUser='root', sshPassword='password', sshPort=22, sshIdSuffix=None, **kwargs):
        """
        Read File buffer data
        """       
        log.sleep(1,"readchannel")
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


def sftpRunCmd(
    sftpHost,
    sftpUser,
    sftpPassword,
    sftpPort,
    sftpId,
    cmd=None,
    localFile=None,
    remoteFile=None,
    localPath=None,
    remotePath=None,
    operation="get"
):
    """
    This help in  perform sftp commands using paramiko Library

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

    Return:
    -------

    status of operation and operation output

    Usage:
    ------

    sftpRunCmd(localFile, remoteFile, localPath, remotePath, sftpHost, sftpUser, sftpPassword, sftpPort, sftpId, operation)

    """

    log.debug(f"LOCAL FILE [ {localFile} ]")
    log.debug(f"LOCAL PATH [ {localPath} ]")
    log.debug(f"REMOTE FILE [ {remoteFile} ]")
    log.debug(f"REMOTE PATH [ {remotePath} ]")
    log.debug(f"M/C: SFTP-HOST [ {sftpHost} ]")
    log.debug(f"M/C: SFTP-USER [ {sftpUser} ]")
    log.debug(f"M/C: SFTP-PASSWORD [ {sftpPassword} ]")
    log.debug(f"M/C: SFTP-PORT [ {sftpPort} ]")
    log.debug(f"M/C: SFTP-ID [ {sftpId} ]")
    log.debug(f"OPERATION [ {operation} ]")

    status = True
    statusOut = None
    # CHECK AND CREATE SFTP CONNECTION
    sftpConnection = None
    sftpHostUnderScore = re.sub(r"\.", "_", sftpHost)
    log.trace(f"UNDERSCORE sftp-host [ {sftpHostUnderScore} ]")
    keyChain = f"{sftpHostUnderScore}.{sftpUser}.{sftpId}"
    log.trace("KEY CHAIN [ %s ]" % keyChain)
    log.trace(SFTP_CONNECTION)
    if keyChain not in SFTP_CONNECTION:
        log.trace("DID NOT FIND SFTP CONNECTION, CREATING A NEW ONE")
        # INSTANTIATE SSH CONNECTION
        try:
            transport = paramiko.Transport((sftpHost, sftpPort))
            transport.connect(username = sftpUser, password = sftpPassword)
            sftpConnection = paramiko.SFTPClient.from_transport(transport)
            SFTP_CONNECTION.setdefault(sftpHostUnderScore, {}).setdefault(sftpUser, {})[sftpId] = sftpConnection
            log.info(f"SFTP CONNECTION TO HOST [{sftpHost}@{sftpPort}] CREATED SUCCESSFULLY")
        except (EOFError, SSHException) as unknown_error:
            log.warning("COULD NOT CONNECT TO HOST [{}]".format(sftpHost))
            log.warning(unknown_error.args[0])
            status = False
            return (status, statusOut)
    else:
        sftpConnection = SFTP_CONNECTION[sftpHostUnderScore][sftpUser][sftpId]

    # MANIPULATE FILE
    if localPath is not None and localFile is not None:
        localFile = f"{localPath}/{localFile}"
    if remotePath is not None and remoteFile is not None:
        remoteFile = f"{remotePath}/{remoteFile}"

    # SFTP OPERATIONS
    try:
        if operation == "get":
            log.info(f"TRANSFERRING FILE [REMOTEHOST: {remoteFile}] TO FILE [LOCALHOST: {localFile}]")
            sftpConnection.get(remoteFile, localFile)
        elif operation == "put":
            log.info(f"TRANSFERRING FILE [LOCALHOST: {localFile}] TO FILE [REMOTEHOST: {remoteFile}]")
            sftpConnection.put(localFile, remoteFile)
        elif operation == "chdir":
            log.info(f"CHANGING DIRECTORY TO [REMOTEHOST: {cmd}]")
            sftpConnection.chdir(cmd)
        elif operation == "listdir":
            if cmd is None:
                cmd = '.'
            log.info(f"LISTIING DIRECTORY TO [REMOTEHOST: {cmd}]")
            statusOut = sftpConnection.listdir(cmd)
            log.info(f"LISTIING DIRECTORY TO [REMOTEHOST: {cmd} OUTPUT: {statusOut}]")
        elif operation == "mkdir":
            log.info(f"CREATING DIRECTORY TO [REMOTEHOST: {cmd}]")
            sftpConnection.mkdir(cmd)
        elif operation == "cwd":
            log.info(f"GET CWD")
            statusOut = sftpConnection.getcwd()
            if statusOut is None:
                statusOut = "/"
            log.info(f"CWD IS [{statusOut}]")
        elif operation == "quit":
            log.info(f"QUIT SFTP CONNECTION")
            statusOut = sftpConnection.close()
            del SFTP_CONNECTION[sftpHostUnderScore][sftpUser][sftpId]
        else:
            log.error("UNSUPPORTED SFTP OPERATION")
            status = False

    except Exception as err:
        log.warning(f"Exception while SFTP operation: [{operation}]")
        log.warning(err)
        statusOut = str(err)
        status = False

    return (status, statusOut)

