import time
import os

class MedirTiempos():
    def __init__(self):
        super().__init__()
        self.tiempos = {}

    def medir(self,iden):
        if self.tiempos.get(iden) is None:
            self.tiempos.update({iden:time.time()})
        else:
            self.tiempos.update({iden:time.time() - self.tiempos[iden]})

    def getResults(self):
        pa = os.getcwd()
        self.__deleteFiles()
        for x in self.tiempos:
            nombre = x.split('_')
            if len(nombre) == 2:
                f = open(f'{pa}\\times\\{nombre[0]}','a+')
                f.write(f'{nombre[1]}:{self.tiempos[x]}\n')
                f.close()
            else:
                f = open(f'{pa}\\times\\{nombre[0]}','a+')
                f.write(f'{nombre[1]}_{nombre[3]}:{self.tiempos[x]}\n')
                f.close()

    def __deleteFiles(self):
        archivos = os.listdir('times')
        for archivo in archivos:
            os.unlink(f'times/{archivo}')