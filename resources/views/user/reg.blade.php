@extends('layout.bst')

@section('content')
<form class="form-signin" action="/user/reg" method="post">
    {{csrf_field()}}
    <h2 class="form-signin-heading">用户注册</h2>
    <label for="inputAge">用户名:</label>
    <input type="text" name="u_name" id="inputAge" class="form-control" placeholder="nickname" required autofocus>

    <label for="inputAge">密码:</label>
    <input type="password" name="u_password" id="inputAge" class="form-control" placeholder="nickname" required autofocus>

    <label for="inputAge">确认密码:</label>
    <input type="password" name="u_password1" id="inputAge" class="form-control" placeholder="nickname" required autofocus>

    <label for="inputAge">年龄:</label>
    <input type="text" name="u_age" id="inputAge" class="form-control" placeholder="nickname" required autofocus>

    <label for="inputAge">Email:</label>
    <input type="email" name="u_email" id="inputAge" class="form-control" placeholder="nickname" required autofocus>

    <button class="btn btn-lg btn-primary btn-block" type="submit">注册</button>
</form>
@endsection
