<?php

namespace App\Http\Controllers\User;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use App\Model\UserModel;
use Illuminate\Support\Facades\Redis;
class UserController extends Controller
{
    //
    //web端登录注册
    public function reg(){
	    return view('user.reg');
    }
    public function doReg(Request $request){
        //echo "<pre>";print_r($_POST);
        $name=$request->input('u_name');
        $password=$request->input('u_password');
        $password1=$request->input('u_password1');
        $age=$request->input('u_age');
        $email=$request->input('u_email');
        if(empty($name)){
            echo "用户名必填";exit;
        }
        if(empty($password)){
            echo "密码必填";exit;
        }
        if(empty($password1)){
            echo "确认密码必填";exit;
        }else if($password!==$password1){
            echo "确认密码必须和密码保持一致";
        }
        if(empty($age)){
            echo "年龄必填";exit;
        }
        if(empty($email)){
            echo "邮箱必填";exit;
        }
        $res=UserModel::where(['name'=>$name])->first();
        //var_dump($res);die;
        if($res){
            echo "该账号已存在";exit;
        }
        $password2=password_hash($password,PASSWORD_BCRYPT);
        $data=[
            'name'=>$name,
            'password'=>$password2,
            'age'=>$age,
            'email'=>$email,
            'reg_time'=>time()
        ];
        //print_r($data);exit;
        $uid=UserModel::insertGetId($data);
        if($uid){
            $token = substr(md5(time().mt_rand(1,99999)),10,10);
            //setcookie('uid',$res->uid,time()+86400,'/','lening.com',false,true);
            setcookie('uid',$uid,time()+86400,'/','wangby.cn',false,false);
            setcookie('token',$token,time()+86400,'/','wangby.cn',false,true);
            $redis_key_web_token='str:u:token:'.$uid;
            Redis::del($redis_key_web_token);
            Redis::hset($redis_key_web_token,'web',$token);
            Redis::expire($redis_key_web_token,86400);
            echo "注册成功";
            header('Refresh:2;url=http://www.wangby.cn/user/center');
        }else{
            echo "注册失败";
        }
    }
    public function login(Request $request){
        if(isset($_COOKIE['uid']) && isset($_COOKIE['token'])){
            //token有效
            $key='str:u:token:'.$_COOKIE['uid'];
            $token=Redis::hget($key,'web');
            $app_token=Redis::hget($key,'app');
            if($_COOKIE['token']==$token){
                //token有效
                if(isset($_SERVER['HTTP_REFERER'])){
                    header('Location:'.$_SERVER['HTTP_REFERER']);
                }else{
                    header('Location:http://www.wangby.cn');
                }
            }
        }
        //未登录
        if(isset($_SERVER['HTTP_REFERER'])){
            $data = [
                'referer'=>$_SERVER['HTTP_REFERER']
            ];
            //var_dump($_COOKIE);
            return view('user.login',$data);
        }else{
            $data = [
                'referer'=>''
            ];
            //var_dump($_COOKIE);
            return view('user.login',$data);
        }

    }
    public function doLogin(Request $request){
        $name=$request->input('u_name');
        $password=$request->input('u_password');
        $referer=$request->input('referer');
        if(empty($name)){
            echo "用户名必填";exit;
        }
        if(empty($password)){
            echo "密码必填";exit;
        }
        $res=UserModel::where(['name'=>$name])->first();
        if($res){
            if(password_verify($password,$res->password)){
                $token = substr(md5(time().mt_rand(1,99999)),10,10);
                setcookie('uid',$res->uid,time()+86400,'/','wangby.cn',false,true);
                setcookie('token',$token,time()+86400,'/','wangby.cn',false,true);

                $request->session()->put('u_token',$token);
                $request->session()->put('uid',$res->uid);
                //header("Refresh:3;url=/user/center");


                $redis_key_web_token='str:u:token:'.$res->uid;
                Redis::del($redis_key_web_token);
                Redis::hset($redis_key_web_token,'web',$token);
                Redis::expire($redis_key_web_token,86400);
                echo "登陆成功";
                if(empty($referer)){
                    header('Refresh:2;url=http://www.wangby.cn');
                }else{
                    if($referer=='http://www.wangby.cn/logou'){
                        header('Refresh:2;url=http://www.wangby.cn');
                    }else{
                        header('Refresh:2;url='.$referer);
                    }
                    //header('Refresh:2;url='.$referer);
                }

            }else{
                echo "账号或密码错误";
            }
        }else{
            echo "账号或密码错误";
        }
    }



    //app登陆
    public function appLogin(Request $request){
       //echo "<pre>";print_r($_POST);echo "</pre>";
        $username=$request->input('username');
        $password=$request->input('password');
        $where=[
            'name'=>$username
        ];
        $userInfo=UserModel::where($where)->first();
        if($userInfo){
            if(password_verify($password,$userInfo->password)){
                $token = substr(md5(time()+$userInfo->uid.mt_rand(1,99999)),10,20);
                $uid=$userInfo->uid;
                $redis_key='str:u:token:'.$uid;

                Redis::del($redis_key);
                Redis::hset($redis_key,'app',$token);
                $response=[
                    'error'=>0,
                    'msg'=>'ok',
                    'token'=>$token
                ];
            }else{
                $response=[
                    'error'=>4001,
                    'msg'=>'密码错误',
                    'token'=>''
                ];
            }
        }else{
            $response=[
                'error'=>4001,
                'msg'=>'账号不存在',
                'token'=>''
            ];
        }
        return $response;
    }
    public function appRegister(Request $request){
        $name=$request->input('name');
        $password=$request->input('password');
        $age=$request->input('age');
        $email=$request->input('email');
        $reg_time=$request->input('reg_time');
        $res=UserModel::where(['name'=>$name])->first();
        if($res){
            $response=[
                'error'=>4001,
                'msg'=>'该账号已存在',
                'token'=>''
            ];
        }else{
            $password2=password_hash($password,PASSWORD_BCRYPT);
            $data=[
                'name'=>$name,
                'password'=>$password2,
                'age'=>$age,
                'email'=>$email,
                'reg_time'=>$reg_time
            ];
            $uid=UserModel::insertGetId($data);
            if($uid){
                $token = substr(md5(time()+$uid.mt_rand(1,99999)),10,10);
                $redis_key='app:login:token:'.$uid;
                Redis::del($redis_key);
                Redis::hset($redis_key,'app',$token);
                $response=[
                    'error'=>0,
                    'msg'=>'ok',
                    'token'=>$token
                ];
            }else{
                $response=[
                    'error'=>4001,
                    'msg'=>'注册失败',
                    'token'=>''
                ];
            }
        }
        return $response;
    }
}
