package com.epita.filrouge.domain.utilisateur;

public enum UtilisateurRoleEnum {
    ROLE_TYPE1(true,false,false,false),
    ROLE_TYPE2(true, true, true, false),
    ROLE_ADMIN(true, true, true, true);

    private Boolean consultation;
    private Boolean modification;
    private Boolean suppression;
    private Boolean admin;

    UtilisateurRoleEnum(Boolean consultation, Boolean modification, Boolean suppression, Boolean admin) {
        this.consultation = consultation;
        this.modification = modification;
        this.suppression = suppression;
        this.admin = admin;
    }

    public Boolean getConsultation() {
        return consultation;
    }

    public Boolean getModification() {
        return modification;
    }

    public Boolean getSuppression() {
        return suppression;
    }

    public Boolean getAdmin() {
        return admin;
    }


}
