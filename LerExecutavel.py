import pefile

class LerExecutavel:

    def listfuncoes(fname):

        peRepresentacao=pefile.PE(fname,fast_load=True)

        if peRepresentacao.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress != 0:
            peRepresentacao.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            if peRepresentacao.DIRECTORY_ENTRY_EXPORT is not None:
                 for exp in peRepresentacao.DIRECTORY_ENTRY_EXPORT.symbols:
                     print(hex(peRepresentacao.OPTIONAL_HEADER.ImageBase + exp.address), exp.name)


LerExecutavel.listfuncoes('C:/Windows/System32/user32.dll')
# MessageBoxA , MessageBoxW