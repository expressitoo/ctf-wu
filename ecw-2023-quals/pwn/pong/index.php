<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PONG</title>
  <style>
 html,body {
  height:100%;
  width:100%;
  margin:0;
}

body {
  background: black;
}

#title {
  color:white;
  position: absolute; 
  top: 0;
  left: 50%;
  transform: translateX(-50%);
  width: 500px;
  overflow: scroll;
}

#form {
  position: absolute;
  bottom: 50%;
  left: 50%;
  transform: translateX(-50%);
  color: white;

}
</style>
</head>

<body>
<canvas id="c"></canvas> 

    <?php
    $succ=0;
    if (is_uploaded_file($_FILES['img']['tmp_name'] ?? '')) {
        $uploaddir = "./uploads/";
        $uploadfile = $uploaddir . basename($_FILES["img"]["tmp_name"]);
        if (!move_uploaded_file($_FILES["img"]["tmp_name"], $uploadfile)) {
            echo '<pre>';
            echo "Hum.\n";
            echo '</pre>';
        }
        else {
            $succ=1;
        }
    }
    if ($succ == 1) {
        echo '<pre id="title">';
        echo(system("./parser $uploadfile"));
        echo '</pre>';
    }
    else {
    ?>
   <div id="title">
        <h1>AI powered image analysis</h1> 
    </div>
    <form id="form" action="" method="post" enctype="multipart/form-data">
        <p>Image:
        <input type="file" name="img" />
        <input type="submit" value="Send" />
        </p>
    </form>
    <?php
        }
    ?>  
</body>
<script>
    var c = document.getElementById("c");
    var ctx = c.getContext("2d");
    c.height = window.innerHeight;
    c.width = window.innerWidth;
    var matrix = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%+-/~{[|`]}";
    matrix = matrix.split("");
    var font_size = 10;
    var columns = c.width/font_size;
    var drops = [];
    for(var x = 0; x < columns; x++)
        drops[x] = 1; 

    function draw()
    {
        ctx.fillStyle = "rgba(0, 0, 0, 0.04)";
        ctx.fillRect(0, 0, c.width, c.height);
        ctx.fillStyle = "#03A062 ";
        ctx.font = font_size + "px arial";
        for(var i = 0; i < drops.length; i++)
        {
            var text = matrix[Math.floor(Math.random()*matrix.length)];
            ctx.fillText(text, i*font_size, drops[i]*font_size);
            if(drops[i]*font_size > c.height && Math.random() > 0.975)
                drops[i] = 0;
            drops[i]++;
        }
    }
    setInterval(draw, 35);
</script>
</html>
