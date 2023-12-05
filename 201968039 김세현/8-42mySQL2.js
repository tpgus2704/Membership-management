// 모듈을 추출합니다.
var fs = require('fs');
var ejs = require('ejs');
var express = require('express');
var bodyParser = require('body-parser');
var mysql = require('mysql');
var session = require('express-session');
var passed = false;

const bcrypt = require('bcrypt');
var axios = require('axios');

function now() {
  var currentdate = new Date();
  var now = currentdate.getFullYear() + "-"
  + Number(currentdate.getMonth()+1) + "-"
  + currentdate.getDate() + " "
  + currentdate.getHours() + ":"
  + currentdate.getMinutes() + ":"
  + currentdate.getSeconds();

  return now;
}

function logging(logstr) {
  fs.appendFile('members.log', logstr+'\n', 'UTF8', function (err) {
    if (err) throw err;
    console.log(logstr);
  });
}
//---------- mySQL 데이터베이스를 구현하는 메소드(실행코드) --------------------

try {
  var client = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '12345678',
    database: 'AITS'
  });
} catch(e) {
  console.log(e.name);
  console.log(e.message);
}
client.connect((err) => {
  if (err) throw err;
  logging('DBMS Connected!----!!');
});

//---------- 서버생성 및 미들웨어 설정 ------

// Server 생성
try {
  var app = express();
  app.use(bodyParser.urlencoded({ // 미들웨어를 설정합니다.
    extended: false
  }));
} catch(e) {
  console.log(e.name);
  console.log(e.message);
}

// Server 실행
app.listen(80, function() {
  logging('Server 실행중: localhost');
});


//***** 세션 설정 코드 ************************************************

app.use(session({
  secret: 'secret key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 30 * 60 * 1000 // 30분 (세션 만료 시간)
  }
}));

// 사용자 인증 미들웨어
app.use(function (request, response, next) {
  if (request.session.user && request.session.cookie.expires > Date.now()) {
    passed = true; // 세션에 사용자 정보가 있으면 로그인 상태로 설정
  } else {
    if (passed) {
      // 세션이 만료되거나 로그아웃된 경우 로그를 남깁니다.
      console.log('Session expired or user logged out.');
    }
    passed = false; // 세션에 사용자 정보가 없거나 만료되었으면 로그아웃 상태로 설정
  }
  next();
});

//***** 회원가입 코드 *****
app.get('/SIGNUP', function (request, response) {
  fs.readFile('Signup.ejs', 'utf8', function (ejserror, ejsdata) {
    response.writeHead(200, { 'Content-Type': 'text/html' });
    response.end(ejs.render(ejsdata, {
    }));
  });
});

app.post('/signup', function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  // 비밀번호 해시 생성
  bcrypt.hash(password, 10, function (err, hash) {
    if (err) {
      console.error(err);
      res.status(500).send('회원가입 중 오류가 발생했습니다.');
      return;
    }

    // 데이터베이스에 회원가입 정보 삽입
    client.query('INSERT INTO PASSWD (ID, PW) VALUES (?, ?)', [username, hash], function (err, result) {
      if (err) {
        console.error(err);
        res.status(500).send('회원가입 중 오류가 발생했습니다.');
        return;
      }
      // 회원가입 성공 시 로그인 페이지로 리다이렉트 또는 다른 동작 수행
      res.redirect('/');
    });
  });
});





//***** ID/PW 입력 코드 ************************************************

app.get('/', function (request, response) {
  fs.readFile('8-42LOGIN.ejs', 'utf8', function (ejserror, ejsdata) {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end(ejs.render(ejsdata, {
      }));
  });
});

//***** ID/PW 입력 코드 ************************************************

app.get('/', function (request, response) {
  fs.readFile('8-42LOGIN.ejs', 'utf8', function (ejserror, ejsdata) {
    response.writeHead(200, { 'Content-Type': 'text/html' });
    response.end(ejs.render(ejsdata, {}));
  });
});

app.post('/', function (request, response) {
  // 변수를 선언합니다.
  var id = request.body.id.trim(); // 공백 제거
  var pw = request.body.pw.trim(); // 공백 제거

  console.log('Debug: ID -', id, ', PW -', pw);

  // 유효성을 검사합니다.
  if (id && pw) {
    client.query('SELECT COUNT(*) no, ID, PW FROM passwd WHERE id = ?', [id],
      function (error, result) {
        if (error) {
          console.error(error);
          response.redirect('/');
          return;
        }

        if (result[0].no == 0) {
          logging('USER <' + id + '> NOT FOUND !!' + '(' + request.connection.remoteAddress.replace(/^.*:/, '') + ')');
          response.redirect('/');
        } else {
          const hashedPassword = result[0].PW;

          console.log('Debug: DB Result -', result);
          console.log('Debug: Hashed Password from DB -', hashedPassword);

          bcrypt.compare(pw, hashedPassword, function (err, passwordMatch) {
            if (err) {
              console.error(err);
              response.redirect('/');
              return;
            }

            console.log('Debug: Password Match -', passwordMatch);

            if (passwordMatch) {
              request.session.user = { id };
              passed = true;
              logging(now() + ' LOGGED IN= ' + id + '(' + request.connection.remoteAddress.replace(/^.*:/, '') + ')');
              response.redirect('/home');
            } else {
              passed = false;
              logging('LOGIN INCORRECT !!' + '(' + request.connection.remoteAddress.replace(/^.*:/, '') + ')');
              response.redirect('/');
            }
          });
        }
      });
  } else {
    response.redirect('/');
  }
});

app.get('/home/auth/kakao/callback', async function (req, res) {
  const { code } = req.query;

  if (!code) {
    console.error('카카오 코드가 전달되지 않았습니다.');
    return res.redirect('/');
  }

  try {
    // 카카오로부터 받은 코드를 사용하여 토큰을 얻는 요청
    const tokenResponse = await axios.post(
      'https://kauth.kakao.com/oauth/token',
      null,
      {
        params: {
          grant_type: 'authorization_code',
          client_id: '1004876', 
          redirect_uri: 'http://localhost/home/auth/kakao/callback', // 등록한 Redirect URI와 일치해야 함
          code: code,
        },
      }
    );

    const accessToken = tokenResponse.data.access_token;

    // 토큰을 사용하여 사용자 정보를 가져오는 요청
    const userResponse = await axios.get('https://kapi.kakao.com/v2/user/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const userInfo = userResponse.data;

    // 여기에서 필요한 로그인 처리를 수행하고, 세션에 사용자 정보를 저장하거나 다른 동작을 수행하세요.
    // 예: 세션에 사용자 ID 저장
    req.session.user = {
      id: userInfo.id,
      // 다른 필요한 사용자 정보 추가
    };

    // 로그인 후 리다이렉트할 페이지로 이동
    res.redirect('/home');
  } catch (error) {
    console.error('카카오 API 호출 중 오류:', error.message);
    res.redirect('/');
  }
});


app.post('/logout', function (request, response) {
  if (request.session.user) {
    logging(now() + ' LOGGED OUT= ' + request.session.user.id + '(' + request.connection.remoteAddress.replace(/^.*:/, '') + ')');
    request.session.destroy(function(err) {
      if (err) {
        console.error('세션 파기 중 오류 발생:', err);
      } else {
        passed = false; // 로그아웃 상태로 설정
        console.log('디버그: /로 리다이렉팅 중'); // 리다이렉트 로그 추가
      }
      response.redirect('/'); // 로그아웃 후 홈페이지로 리다이렉트 또는 다른 동작 수행
    });
  } else {
    passed = false; // 로그아웃 상태로 설정
    console.log('디버그: /로 리다이렉팅 중'); // 리다이렉트 로그 추가
    response.redirect('/'); // 세션이 없거나 이미 파기된 경우 홈페이지로 리다이렉트 또는 다른 동작 수행
  }
});

//***** 홈화면출력 코드 *****
app.get('/HOME', function (request, response) {
  // 사용자가 로그인하지 않았을 때, 'passed'를 실제 로그인 상태 표시기로 바꿔주세요
  if (passed == true) {
    fs.readFile('8-42HOME.ejs', 'utf8', function (ejserror, ejsdata) {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end(ejs.render(ejsdata, {}));
    });
  } else {
    response.redirect('/');
    return;
  }
});



//***** 자료출력 코드 *****
app.get('/list', function (request, response) {
  if(passed==true) {
    console.log('app.get/list: '+passed);

    fs.readFile('8-42LIST.ejs', 'utf8', function (ejserror, ejsdata) {
      client.query('SELECT * FROM members ORDER BY id', function(error, result){
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end(ejs.render(ejsdata, {
          data : result
        }));
      });
    });
  }  else {
    console.log('app.get/list: '+ passed);
    response.redirect('/');
  }
});

//***** 자료입력 코드 *****

app.get('/insert', function (request, response) {
  if (passed) {
    // Assume you have a query to get data from the database, modify as needed
    client.query('SELECT * FROM members ORDER BY id', function (error, result) {
      if (error) {
        console.error(error);
        // Handle the error, send a response, or redirect as needed.
      }

      fs.readFile('8-42POST.ejs', 'utf8', function (ejserror, ejsdata) {
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end(ejs.render(ejsdata, {
          data: result // 'data'를 정의하여 전달합니다.
        }));
      });
    });
  } else {
    console.log('app.get/insert: ' + passed);
    response.redirect('/');
  }
});

app.post('/insert', function (request, response) {
  // 변수를 선언합니다.
  var name = request.body.name;
  var region = request.body.region;
  

  // 유효성을 검사합니다.
  if(passed) {
    if (name && region) {
      logging(now() + ' INSERT= '+ name+','+ region +'('+request.connection.remoteAddress.replace(/^.*:/, '') + ')');
      client.query('INSERT INTO members (ID, NAME, REGION) VALUES (?, ?, ?)',
            [, name, region],
            function(err, res){  // ID=Null 이 들어가야 하므로 ID 값은 없음
        if (err) logging(err);
        client.query('SELECT * FROM members ORDER BY id', function(error, result){
  //        console.log(result);
        });
        response.redirect('/insert');
      });
    } else {
        response.redirect('/insert');
    }
  }  else {
    console.log('app.post/insert: '+ passed);
    response.redirect('/');
  }
});

//***** 자료수정 코드 *****
app.get('/edit', function (request, response) {
  if(passed) {
    fs.readFile('8-42EDIT.ejs', 'utf8', function (ejserror, ejsdata) {
      client.query('SELECT * FROM members ORDER BY id', function(error, result){
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end(ejs.render(ejsdata, {
          data : result
        }));
      });
    });
  }  else {
    console.log('app.get/edit: '+ passed);
    response.redirect('/');
  }
});

app.post('/edit', function (request, response) {
  // 변수를 선언합니다.
  var id = request.body.id;
  var name = request.body.name;
  var region = request.body.region;

  // 데이터베이스를 수정합니다.
  if(passed) {
    if (name && region) {
      logging(now() + ' EDIT= '+ id +':'+ name+','+ region +'('+request.connection.remoteAddress.replace(/^.*:/, '') + ')');
      fs.readFile('8-42EDIT.ejs', 'utf8', function (ejserror, ejsdata) {
        client.query('UPDATE members SET NAME = ?, REGION = ? WHERE ID = ? ORDER BY id', [name, region, id], function(error, result){
          if(error) logging(error);
          client.query('SELECT * FROM members ORDER BY id', function(error, result){
            response.writeHead(200, { 'Content-Type': 'text/html' });
            response.end(ejs.render(ejsdata, {
              data : result   // 필드명이 대문자이면 ejsHTML문서에서도 대문자여야 함
            }));
          });
        });
      });
    } else {
      response.redirect('/edit');
    }
  }  else {
    console.log('app.post/edit: '+ passed);
    response.redirect('/');
  }
});

//***** 자료삭제 코드 *****
app.get('/del', function (request, response) {
  if(passed) {
    fs.readFile('8-42DEL.ejs', 'utf8', function (ejserror, ejsdata) {
      client.query('SELECT * FROM members ORDER BY id', function(error, result){
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end(ejs.render(ejsdata, {
          data : result
        }));
      });
    });
  }  else {
    console.log('app.get/del: '+ passed);
    response.redirect('/');
  }
});

app.post('/del', function (request, response) {
  if(passed) {
    var theid = request.body.id;
    logging(now() + ' DELETE= '+ theid +'('+request.connection.remoteAddress.replace(/^.*:/, '') + ')');
    fs.readFile('8-42DEL.ejs', 'utf8', function (ejserror, ejsdata) {
      client.query('DELETE FROM members WHERE ID = ? ORDER BY id', [theid], function(error, result){
        if(error) logging(error);
        client.query('SELECT * FROM members ORDER BY id', function(error, result){
          response.writeHead(200, { 'Content-Type': 'text/html' });
          response.end(ejs.render(ejsdata, {
            data : result   // 필드명이 대문자이면 ejsHTML문서에서도 대문자여야 함
          }));
        });
      });
    });
  }  else {
    console.log('app.post/list: '+ passed);
    response.redirect('/');
  }
});

//***** 자료검색 코드 *****
app.get('/find', function (request, response) {
  if(passed) {
    fs.readFile('8-42FIND.ejs', 'utf8', function (ejserror, ejsdata) {
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end(ejs.render(ejsdata, {
          data : [{}]   // 객체 1개가 아닌 여러개를 넘기는 방법 (for문으로 돌릴 때)
        }));
    });
  }  else {
    console.log('app.get/find: '+ passed);
    response.redirect('/');
  }
});

app.post('/find', function (request, response) {
  if(passed) {
    var thename = request.body.name;
    logging(now() + ' FIND= '+ thename +'('+request.connection.remoteAddress.replace(/^.*:/, '') + ')');
    fs.readFile('8-42FIND.ejs', 'utf8', function (ejserror, ejsdata) {
      client.query('SELECT * FROM members WHERE name = ? ORDER BY id', [thename], function(error, result){
        if(error) logging(error);
  //      console.log(result);
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end(ejs.render(ejsdata, {
          data : result   // 필드명이 대문자이면 ejsHTML문서에서도 대문자여야 함
        }));
      });
    });
  }  else {
    console.log('app.post/find: '+ passed);
    response.redirect('/');
  }
});
