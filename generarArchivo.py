import os
import random

working_directory = os.getcwd()

f = open(working_directory + "/documentos/archivoAleatorio5.txt", "w")

size = random.randint(100000,120000)

for k in range(0,size):
    for j in range(0,63):
        for i in range(0,16):
            f.write(str(i))

f.close()