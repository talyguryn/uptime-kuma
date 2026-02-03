exports.up = function (knex) {
    return knex.schema.alterTable("domain_expiry", function (table) {
        table.json("whois_info").defaultTo(null);
    });
};

exports.down = function (knex) {
    return knex.schema.alterTable("domain_expiry", function (table) {
        table.dropColumn("whois_info");
    });
};
