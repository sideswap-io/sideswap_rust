create table addresses (
    ind int primary key not null,
    address text unique not null,
    user_note text
);
