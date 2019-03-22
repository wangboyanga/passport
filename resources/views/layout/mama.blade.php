<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>@yield('title')</title>
</head>
<body>
    @section('header')
        mama
    @show
    @yield('content')

    @section('footer')
        mama
    @show
</body>
</html>