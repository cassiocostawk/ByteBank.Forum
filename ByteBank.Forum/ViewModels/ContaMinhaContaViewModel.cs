using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace ByteBank.Forum.ViewModels
{
    public class ContaMinhaContaViewModel
    {
        [Required]
        [Display(Name = "Nome Completo")]
        public string NomeCompleto { get; set; }

        [Display(Name = "Número de Celular")]
        public string NumeroDeCelular { get; set; }

        [Display(Name = "Habilitar Autenticação de Dois Fatores")]
        public bool HabilitarAutenticacaoDeDoisFatores { get; set; }

        public bool NumeroDeCelularConfirmado { get; set; }
    }
}