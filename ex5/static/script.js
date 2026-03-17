function showSteps(steps){

let consoleBox=document.getElementById("console")

consoleBox.innerHTML=""

steps.forEach((step)=>{

let line=document.createElement("p")

line.innerText=step

consoleBox.appendChild(line)

})

}


function generateRSA(){

let plaintext=document.getElementById("plaintext").value

if(plaintext==""){
alert("Enter plaintext first")
return
}

fetch("/generate_rsa",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({
plaintext:plaintext
})

})

.then(response=>response.json())

.then(data=>{
showSteps(data.steps)
})

}


function generateDiffie(){

let p=document.getElementById("p").value
let g=document.getElementById("g").value
let a=document.getElementById("a").value
let b=document.getElementById("b").value

fetch("/generate_diffie",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({
p:p,
g:g,
a:a,
b:b
})

})

.then(response=>response.json())

.then(data=>{

showSteps(data.steps)

})

}