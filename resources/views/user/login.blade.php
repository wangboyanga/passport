@extends('layout.bst')

@section('content')
<form class="form-signin" action="/user/login" method="post">
    {{csrf_field()}}
    <h2 class="form-signin-heading">请登录</h2>
    <label for="inputEmail">用户名:</label>
    <input type="text" name="u_name" id="inputEmail" class="form-control" placeholder="name" required autofocus>
    <input type="hidden" name="referer" value="{{$referer}}">
    <label for="inputPassword" >密码:</label>
    <input type="password" name="u_password" id="inputPassword" class="form-control" placeholder="***" required>
    <div class="checkbox">
        <label style="width:500px">
            <input type="checkbox" value="remember-me"> Remember me
        </label>
        <a href="https://open.weixin.qq.com/connect/qrconnect?appid=wxe24f70961302b5a5&amp;redirect_uri=http%3a%2f%2fmall.77sc.com.cn%2fweixin.php%3fr1%3dhttp%3a%2f%2fwww.wangby.cn%2fweixin%2fgetcode&amp;response_type=code&amp;scope=snsapi_login&amp;state=STATE#wechat_redirect">微信登陆</a>
    </div>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
</form>
@endsection