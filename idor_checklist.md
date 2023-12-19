### IDOR Access Violations Checklist

- [ ] **Horizontal IDOR**
    - [ ] Proper authorization checks are implemented to ensure users can only access their own data.

- [ ] **Vertical IDOR**
    - [ ] Proper access controls are in place to prevent users from accessing higher privilege data/functions.

- [ ] **Object-level IDOR**
    - [ ] Fine-grained access controls are implemented to restrict users from modifying or deleting objects they don't own.

- [ ] **Function-level IDOR**
    - [ ] Role-based access controls are implemented to restrict users from accessing functions or actions beyond their role.

- [ ] **Mass Assignment IDOR**
    - [ ] User inputs are validated and sanitized to prevent manipulation of object properties.

- [ ] **Business Logic IDOR**
    - [ ] Server-side validation and logic checks are implemented to ensure business rules are not violated.

- [ ] **API IDOR**
    - [ ] APIs are secured with proper authentication, authorization, and input validation to prevent IDOR attacks.