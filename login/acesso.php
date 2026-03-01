<?php
// login.php

// session_start();
// include 'conexao.php';  // sua conexão com o banco

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario = trim($_POST['usuario'] ?? '');
    $senha   = trim($_POST['senha']   ?? '');

    // aqui você faria a validação no banco
    // exemplo: SELECT * FROM usuarios WHERE login = ? AND senha = ?

    // se der certo:
    // $_SESSION['logado'] = true;
    // header("Location: dashboard.php");
    // exit;

    // se der errado:
    // $erro = "Usuário ou senha inválidos";
}
?>

<!-- Depois inclua o HTML e mostre $erro se existir -->