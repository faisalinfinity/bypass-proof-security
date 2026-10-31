<?php
$r = mysqli_query($db, "SELECT * FROM u WHERE id = $_GET[id]");                  // EXPECT sqli-interpolated
$data = unserialize($_COOKIE['prefs']);                                           // EXPECT unsafe-deserialization
include($_GET['page'] . '.php');                                                  // EXPECT path-user-input
system("ping " . $_GET['host']);                                                  // EXPECT cmd-injection
header("Location: " . $_GET['next']);                                             // EXPECT open-redirect
class User extends Model { protected $guarded = []; }                             // EXPECT mass-assignment
