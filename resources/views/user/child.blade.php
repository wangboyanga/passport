@extends('layout.mama')
@section('title') {{ $title }} @endsection
@section('header') @parent child @endsection
@section('content')
    <table border="1">
        <thead>

        </thead>
        <tbody>
        @foreach($list as $v)
        <tr>
            <td>{{$v['uid']}}</td>
            <td>{{$v['name']}}</td>
            <td>{{$v['age']}}</td>
            <td>{{$v['email']}}</td>
        </tr>
        @endforeach
        </tbody>
    </table>
@endsection
@section('footer') child @parent  @endsection

