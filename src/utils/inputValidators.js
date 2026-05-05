export function usernameValidator(username) {
    
    const cleanUsername = username.replace(/\s/g, "").toLowerCase(); // remove whitespaces
    const alphabetsOnly = /^[a-zA-Z]+$/;
    return alphabetsOnly.test(cleanUsername)

}

export function emailValidator(email) {

    const cleanEmail = email.replace(/\s/g, "").toLowerCase();
    const emailPattern = /^\S+@\S+\.\S+$/;
    return emailPattern.test(email)

}

export function cleanUserInput(input) {

    const cleanInput = input.replace(/\s/g, "").toLowerCase(); 
    return cleanInput;

}