# Roles

Roles can be assigned to users and administrators. Admins with a role are limited administrators, they can only view and manage users with their own role and they cannot have the following permissions:

- manage_admins
- manage_system
- manage_event_rules
- manage_roles
- view_events

Users created by role administrators automatically inherit their role.

Admins without a role are global administrators and can manage all users (with and without a role) and assign a specific role to users.
