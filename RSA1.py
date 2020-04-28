import os
import time

from RSA import RSA
from AES import AES
from KDF import KDF
from Certificate import Certificate
from MedirTiempos import MedirTiempos

llaves = {128:3072, 192:7680, 256:15380}

origen = RSA()
receptor = RSA()

tiempos = MedirTiempos()

documentos = os.listdir('documentos')
iv = os.urandom(16)

for x in llaves:
    bits = int(x/8)

    # Se genera llave k para AES
    k = KDF().getAKey(bits)

    # Se obtienen las llaves asimetricas ya generadas desde un archivo (por cuestiones de tiempo)
    receptor.getKeys('receptor_keys',llaves[x])
    origen.getKeys('emitter_keys',llaves[x])

    # Lado cifrado
    # Se genera un certificado para las llaves del origen
    cer = Certificate(origen.getPrivateKey(),origen.getPublicKey())
    certificado = cer.getCertificate()
    # Se pasa la llave publica del receptor al origen
    origen.setEntityKey(receptor.getPublicKey())

    ########## Tiempo de cifrado ###############
    # Se cifra con la llave de la otra entidad
    tiempos.medir(f'cifradollave_{x}')
    cypherKey = origen.encrypt(k)
    tiempos.medir(f'cifradollave_{x}')
    ############################################
    
    # Se cifran los documentos
    for documento in documentos:
        # Se instancia el cifrador simetrico
        aeso = AES(k,iv)

        # Se lee el archivo
        f = open(f'documentos/{documento}','rb')
        contenido = f.read()
        f.close()

        ########## Tiempo de cifrado ###############
        # Se cifra el contenido de cada archivo
        tiempos.medir(f'cifrado_{documento}_llave_{x}')
        cyphertext = aeso.encrypt(contenido)
        tiempos.medir(f'cifrado_{documento}_llave_{x}')
        ############################################

        # Se retira la extension [opcional]
        nombre = documento.split('.')

        ########## Tiempo de firmado ###############
        # Se firma el contenido
        tiempos.medir(f'firmado_{documento}_llave_{llaves[x]}')
        firma = origen.sign(contenido)
        tiempos.medir(f'firmado_{documento}_llave_{llaves[x]}')
        ############################################

        # Se guarda el archivo cifrado y la firma en otro documento
        f = open(f'documcifrados/{nombre[0]}','wb')
        f.write(cyphertext + b'firma' + firma)
        f.close()

    # Lado decifrado
    # Se obtiene la llave pública para verificar firmas
    receptor.setEntityKey(origen.getPublicKey())

    ########## Tiempo de verificación de certificado ###############
    # Se verifica la autenticidad de la llave con el certificado
    tiempos.medir(f'verificacioncertificado_{llaves[x]}')
    esCorrecto = cer.validateCertificate(certificado,receptor.getEntityKey())
    tiempos.medir(f'verificacioncertificado_{llaves[x]}')
    ################################################################
    
    if esCorrecto:
        ########## Tiempo de descifrado ###############
        # Se descifra la llave enviada por el origen
        tiempos.medir(f'descifradollave_{x}')
        key = receptor.decrypt(cypherKey)
        tiempos.medir(f'descifradollave_{x}')
        ###############################################

        # Se decifran los documentos
        for documento in documentos:
            # Se instancia el cifrador con la llave recibida
            aesr = AES(key,iv)

            # Se lee el archivo
            nombre = documento.split('.')
            f = open(f'documcifrados/{nombre[0]}','rb')
            contenido = f.read()
            f.close()
            # Se separa la firma del contenido
            contenido = contenido.split(b'firma')

            ########## Tiempo de descifrado ###############
            # Se obtiene el contenido del archivo
            tiempos.medir(f'descifrado_{documento}_llave_{x}')
            text = aesr.decrypt(contenido[0])
            tiempos.medir(f'descifrado_{documento}_llave_{x}')
            ###############################################

            ########## Tiempo de verificación firmas ###############
            # Se verifica la integridad de los datos
            tiempos.medir(f'verificacionfirmado_{documento}_llave_{llaves[x]}')
            coinciden = receptor.verify(contenido[1],text)
            tiempos.medir(f'verificacionfirmado_{documento}_llave_{llaves[x]}')
            ########################################################

            # Si coinciden se guarda la información en un archivo
            if coinciden:
                # Se guarda el resultado
                f = open(f'documdecifrados/{documento}','wb')
                f.write(text)
                f.close()

tiempos.getResults()