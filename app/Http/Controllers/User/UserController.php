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
            setcookie('uid',$uid,time()+86400,'/','test.com',false,false);
            setcookie('token',$token,time()+86400,'/','test.com',false,true);
            $redis_key_web_token='str:u:token:web:'.$uid;
            Redis::set($redis_key_web_token,$token);
            Redis::expire($redis_key_web_token,86400);
            echo "注册成功";
            header('Refresh:2;url=http://shop.test.com/user/center');
        }else{
            echo "注册失败";
        }
    }
    public function login(Request $request){
        if(isset($_COOKIE['uid']) && isset($_COOKIE['token'])){
            //token有效
            if(isset($_SERVER['HTTP_REFERER'])){
                header('Location:'.$_SERVER['HTTP_REFERER']);
            }else{
                header('Location:http://shop.test.com');
            }
        }else{
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
                setcookie('uid',$res->uid,time()+86400,'/','test.com',false,true);
                setcookie('token',$token,time()+86400,'/','test.com',false,true);

                $request->session()->put('u_token',$token);
                $request->session()->put('uid',$res->uid);
                header("Refresh:3;url=/user/center");


                $redis_key_web_token='str:u:token:web:'.$res->uid;
                Redis::set($redis_key_web_token,$token);
                Redis::expire($redis_key_web_token,86400);
                echo "登陆成功";
                if(empty($referer)){
                    header('Refresh:2;url=http://shop.test.com');
                }else{
                    header('Refresh:2;url='.$referer);
                }

            }else{
                echo "账号或密码错误";
            }
        }else{
            echo "账号或密码错误";
        }
    }
}
