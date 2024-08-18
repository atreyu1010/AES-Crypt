Aquí tienes un ejemplo de un archivo `README.md` para tu software de encriptación y desencriptación de archivos usando AES-256:

---

# AES Cripto

**AES Cripto** es un software de línea de comandos escrito en Python que permite encriptar y desencriptar archivos o directorios completos utilizando el algoritmo de encriptación AES-256. Este script es ideal para proteger tus archivos sensibles con una contraseña segura.

## Características

- **Encriptación de archivos individuales**: Protege tus archivos mediante encriptación AES-256.
- **Desencriptación de archivos**: Recupera tus archivos originales mediante desencriptación.
- **Soporte para directorios**: Encripta o desencripta todos los archivos dentro de un directorio de manera recursiva.
- **Eliminación de archivos originales**: El archivo original es eliminado automáticamente después de la encriptación o desencriptación, dejando solo el archivo resultante.

## Requisitos

- Python 3.6 o superior
- Biblioteca `cryptography`

Puedes instalar la biblioteca `cryptography` ejecutando:

```bash
pip install cryptography
```

## Uso

### Encriptar un archivo

Para encriptar un archivo, usa el siguiente comando:

```bash
python Soft.py -a "ruta/al/archivo.txt" -p "tu_contraseña_secreta"
```

El archivo encriptado tendrá la misma ruta y nombre, con la extensión `.enc` agregada.

### Desencriptar un archivo

Para desencriptar un archivo previamente encriptado, usa el siguiente comando:

```bash
python Soft.py -s "ruta/al/archivo.txt.enc" -p "tu_contraseña_secreta"
```

El archivo desencriptado tendrá la misma ruta y nombre, sin la extensión `.enc`.

### Encriptar todos los archivos en un directorio

Para encriptar todos los archivos dentro de un directorio (de manera recursiva), usa:

```bash
python Soft.py -a "ruta/al/directorio" -p "tu_contraseña_secreta"
```

### Desencriptar todos los archivos en un directorio

Para desencriptar todos los archivos dentro de un directorio (de manera recursiva), usa:

```bash
python Soft.py -s "ruta/al/directorio" -p "tu_contraseña_secreta"
```

### Ayuda

Puedes ver las opciones disponibles ejecutando:

```bash
python Soft.py -help
```

Esto mostrará las opciones y la versión del software.

## Ejemplos

- **Encriptar un archivo**:
  ```bash
  python Soft.py -a "DOCUMENTO PRUEBA.txt" -p "MiContraseñaSegura"
  ```
  Esto generará `DOCUMENTO PRUEBA.txt.enc` y eliminará el archivo original.

- **Desencriptar un archivo**:
  ```bash
  python Soft.py -s "DOCUMENTO PRUEBA.txt.enc" -p "MiContraseñaSegura"
  ```
  Esto generará `DOCUMENTO PRUEBA.txt` y eliminará el archivo encriptado.

## Advertencias

- Asegúrate de recordar la contraseña utilizada para encriptar tus archivos, ya que no hay forma de recuperar los archivos si la olvidas.
- Este software elimina los archivos originales tras encriptar o desencriptar. Úsalo con precaución.

## Contribuciones

Si deseas contribuir al desarrollo de **AES Cripto**, puedes hacerlo mediante pull requests en el repositorio oficial. Por favor, asegúrate de seguir las pautas de contribución.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

---

Este `README.md` proporciona una guía completa sobre cómo utilizar el software y puede ser adaptado según sea necesario.