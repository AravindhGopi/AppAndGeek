@extends('layouts.app')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">Users</div>

                <div class="card-body">
                    @if (session('status'))
                        <div class="alert alert-success" role="alert">
                            {{ session('status') }}
                        </div>
                    @endif
                    
                    <table class="table table-bordered">
                        <tr>
                            <th>S.No</th>
                            <th>Name</th>
                            <th>Email</th>
                        </tr>
                        @foreach ($users as $key=>$user)
                            <tr>
                                <td>{{$key+1}}</td>
                                <td>{{$user['name']}}</td>
                                <td>{{$user['email']}}</td>
                            </tr>
                        @endforeach
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
