-- Table: tb_usuarios

-- DROP TABLE tb_usuarios;

CREATE TABLE tb_usuarios
(
  id serial NOT NULL,
  login character varying(255),
  password character varying(255),
  CONSTRAINT tb_usuarios_pkey PRIMARY KEY (id),
  CONSTRAINT uk_9v12hr9s4xeuggcy1ss95jmwy UNIQUE (login)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE tb_usuarios
  OWNER TO postgres;
