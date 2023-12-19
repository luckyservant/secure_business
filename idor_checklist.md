### IDOR Access Violations Checklist

- [ ] **Horizontal IDOR**
    - **Description:** An entity is able to access data of other users at the same privilege level, such as viewing someone else's profile.
    - **Mitigation:** Implement proper authorization checks to ensure users can only access their own data.
    - **Example:** Ensure that when fetching user data, the system verifies the requesting user's identity and only returns data associated with that user.

- [ ] **Vertical IDOR**
    - **Description:** An entity can access data requiring a higher privilege level, for example, accessing admin-only functionality.
    - **Mitigation:** Enforce access controls to prevent users from accessing higher privilege data/functions.
    - **Example:** If an admin page is accessed, verify that the authenticated user has the necessary admin role before allowing access.

- [ ] **Object-level IDOR**
    - **Description:** An entity can modify or delete an object that they should not be able to modify or delete, like editing someone else's post.
    - **Mitigation:** Implement fine-grained access controls to restrict users from modifying or deleting objects they don't own.
    - **Example:** For a social media platform, when a user tries to delete a post, verify that the post belongs to the authenticated user.

- [ ] **Function-level IDOR**
    - **Description:** An entity can access a function or action they shouldn't, such as triggering an administrative actions.
    - **Mitigation:** Implement proper role-based access controls to restrict users from accessing functions or actions beyond their role.
    - **Example:** Allow only users with the "Manager" role to approve expense reports.

- [ ] **Mass Assignment IDOR**
    - **Description:** Improper input allows attackers to manipulate object properties, leading to unauthorized data changes.
    - **Mitigation:** Apply Allowlist to bind input to backend objects. E.g In Spring MVC use **binder.setAllowedFields(["userid","password","email"])** to only bind html elements to model object
    - **Example:** When updating user profile details, only allow specific properties (e.g., name, email) to be modified through the API.

- [ ] **Business Logic IDOR**
    - **Description:** Occurs when business logic is exploited to access or modify data in unintended ways.
    - **Mitigation:** Implement server-side validation and logic checks to ensure business rules are not violated.
    - **Example:** If an e-commerce application calculates discounts based on user type, ensure that the server recalculates discounts rather than relying solely on client-side input.
