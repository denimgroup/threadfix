package com.denimgroup.threadfix.data.entities;

import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "CustomCweText")
public class CustomCweText extends AuditableEntity {

    @NotNull
    private GenericVulnerability genericVulnerability;

    @NotEmpty
    private String customText;

    @ManyToOne
    @JoinColumn(name = "genericVulnerabilityId")
    public GenericVulnerability getGenericVulnerability() {
        return genericVulnerability;
    }

    public void setGenericVulnerability(GenericVulnerability genericVulnerability) {
        this.genericVulnerability = genericVulnerability;
    }

    @Column
    public String getCustomText() {
        return customText;
    }

    public void setCustomText(String customText) {
        this.customText = customText;
    }
}
