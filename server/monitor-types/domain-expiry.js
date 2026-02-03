const { MonitorType } = require("./monitor-type");
const { UP } = require("../../src/util");
const DomainExpiry = require("../model/domain_expiry");

class DomainExpiryMonitorType extends MonitorType {
    name = "domain-expiry";

    /**
     * @inheritdoc
     */
    async check(monitor, heartbeat, _server) {
        const supportInfo = await DomainExpiry.checkSupport(monitor);
        const expiryDate = await DomainExpiry.checkExpiry(supportInfo.domain);

        if (!expiryDate || Number.isNaN(expiryDate.getTime())) {
            throw new Error(`No registry expiry date was found for domain ${supportInfo.domain}`);
        }

        const domain = await DomainExpiry.findByDomainNameOrCreate(supportInfo.domain);
        const daysRemaining = domain.daysRemaining;

        if (daysRemaining < 0) {
            throw new Error(
                `Domain ${supportInfo.domain} expired ${Math.abs(daysRemaining)} day${Math.abs(daysRemaining) === 1 ? "" : "s"} ago`
            );
        }

        heartbeat.status = UP;
        heartbeat.msg = `${supportInfo.domain} expires in ${daysRemaining} days (${expiryDate.toISOString()})`;
    }
}

module.exports = {
    DomainExpiryMonitorType,
};
