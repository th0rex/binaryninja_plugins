import os
import pefile
import tempfile

from binaryninja import Symbol, SymbolType
from binaryninja.log import log_info
from binaryninja.plugin import BackgroundTaskThread, PluginCommand

def resolve_ordinals(bv):
    class Resolver(BackgroundTaskThread):
        def __init__(self, bv):
                BackgroundTaskThread.__init__(self, "Resolving Ordinals", True)
                self.bv = bv

                # Write the binary to disk so that pefile can read it
                self.binary = tempfile.NamedTemporaryFile()
                self.binary.write(bv.file.raw.read(0, len(bv.file.raw)))
                self.binary.flush()

        def run(self):
            binary = pefile.PE(self.binary.name)

            names = dict()
            for entry in binary.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    names[imp.address] = "{}!{}".format(entry.dll[:-4], imp.name)
            for symbol in self.bv.get_symbols_of_type(SymbolType.ImportAddressSymbol):
                if "Ordinal_" in symbol.name and symbol.address in names:
                    bv.define_user_symbol(Symbol(symbol.type, symbol.address, names[symbol.address]))

    r = Resolver(bv)
    r.start()

def is_pe_file(bv):
    return bv.view_type == 'PE'

PluginCommand.register(
        "Try resolve Ordinals",
        "Try to resolve names of ordinals that binary ninja could not resolve",
        resolve_ordinals,
        is_pe_file
        )

