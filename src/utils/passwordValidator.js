import PasswordValidator from "password-validator";

const schema = new PasswordValidator();

schema
  .is().min(8) 
  .is().max(100) 
  .has().uppercase() 
  .has().lowercase() 
  .has().digits(1) 
  .has().not().spaces(); 


export default function passwordValidator(password) {

    const failedRules = schema.validate(password, { list: true });
    const errorMessages = {
      min: "Password must be at least 8 characters",
      max: "Password must be less than 100 characters",
      uppercase: "Password must have an uppercase letter",
      lowercase: "Password must have a lowercase letter",
      digits: "Password must have at least one digit",
      spaces: "Password should not contain spaces",
    };

    return failedRules.map((rule) => errorMessages[rule] || rule);

}