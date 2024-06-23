from havoc import Demon, RegisterCommand, RegisterModule
from pathlib import Path
from os.path import exists, split, sep, dirname
from struct import pack, calcsize
import havoc

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addbytes(self, b):
        if b is None:
            b = b''
        fmt = "<L{}s".format(len(b))
        self.buffer += pack(fmt, len(b), b)
        self.size += calcsize(fmt)

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s) + 1, s)
        self.size += calcsize(fmt)

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4

def ppid( demon_id, *args ):
    task_id: str    = None
    demon  : Demon  = None
    packer : Packer = Packer()    
    PPid   : int    = None

    demon = Demon( demon_id )

    if len(args) != 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough argument")

    PPid = int(args[0])

    packer.addint(PPid)

    demon.InlineExecute( task_id, "go", "./spawn.x64.o", packer.getbuffer(), False )

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked the demon for spoofing ppid to {ppid}")

    return task_id

def argue( demon_id, *args ):
    task_id: str    = None
    demon  : Demon  = None
    packer : Packer = Packer()
    argue  : str    = None

    demon = Demon( demon_id )

    argue = args[0]

    packer.addstr(argue)

    #task = demon.

def blockdlls( demon_id, *args ):
    task_id:str = None

def run( demon_id, *args ):
    task_id : str    = None
    demon   : Demon  = None
    packer  : Packer = Packer()
    
    ProcName: str    = None
    CmdLine : str    = None
    CurDir  : str    = None
    PPid    : int    = None

    demon = Demon( demon_id )

    if len(args) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    ProcName = args[0]
    CmdLine  = args[1]
    last_backslash_index = ProcName.rfind('\\')

    if not exists(CmdLine):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Path '{CmdLine}' does not exist")

    if last_backslash_index != -1:
        CurDir = ProcName[:last_backslash_index]
    else:
        CurDir = ""

    packer.addstr( "\\??\\" + ProcName )
    packer.addstr( ProcName + " " + CmdLine )
    packer.addstr( CurDir )

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked the demon to execute spawn process - Process Path = {ProcName} - Command Line = {CmdLine} - Process Directory = {CurDir}")

    demon.InlineExecute( task_id, "go", "./spawn.x64.o", packer.getbuffer(), False )

    return task_id

RegisterModule( "spawn", "spawn process with options like ppid, argument spoofing and block dll policy", "", "[options] (args)", "", "" )
RegisterCommand( run, "spawn", "run", "run process", 0, "[executable path] [process argument]", "C:\Windows\System32\cmd.exe dir" )
RegisterCommand( ppid, "spawn", "ppid", "set ppid to spoofing", 0, "[ppid to spoofing]", "1234" )
RegisterCommand( argue, "spawn", "argue", "set argument fake to spoofing", 0, "[fake argument]", "C:\Windows\System32\cmd.exe")
RegisterCommand( blockdlls, "spawn", "blockdlls", "blocks non-Microsoft dlls from being attached to the process", 0, "[boolean value]", "true" )

