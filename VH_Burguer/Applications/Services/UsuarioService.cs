using System.Security.Cryptography;
using System.Text;
using VH_Burguer.Domains;
using VH_Burguer.DTOs;
using VH_Burguer.Exceptions;
using VH_Burguer.Interfaces;

namespace VH_Burguer.Applications.Services
{
    public class UsuarioService
    {
        private readonly iUsuarioRepository _repository;

        // implementando o repositorio e o service so depende da interface
        public UsuarioService(iUsuarioRepository repository)
        {
            _repository = repository;
        }

        // private pq o metodo nao eh regra de negocio e nao faz sentido existir fora do UsuarioService
        private static LerUsuarioDto LerDto(Usuario usuario)// pega a entidade usuario e gera um DTO
        {
            LerUsuarioDto LerUsuario = new LerUsuarioDto
            {
                UsuarioID = usuario.UsuarioID,
                Nome = usuario.Nome,
                Email = usuario.Email,
                StatusUsuario = usuario.StatusUsuario ?? true // garantir que tera um estado true no banco
            };
            return LerUsuario;
        }

        public List<LerUsuarioDto> Listar()
        {
            List<Usuario> usuarios = _repository.Listar();
            List<LerUsuarioDto> usuariosDto = usuarios.Select(usuarioBanco => LerDto(usuarioBanco)) //Select que percorre cada usuario
                .ToList();
            return usuariosDto;

        }

        private static void ValidarEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email) || !email.Contains("@"))
            {
                throw new DomainException("Email invalido.");
            }
        }

        private static byte[] HashSenha(string senha)
        {
            if (string.IsNullOrWhiteSpace(senha))
            {
                throw new DomainException("Senha e obrigatoria.");
            }

            using var sha256 = SHA256.Create(); // gera um hash SHA256 e devolve em byte[]
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(senha));
        }
        public LerUsuarioDto ObterPorId(int id)
        {
            Usuario? usuario = _repository.ObterPorId(id);

            if (usuario == null)
            {
                throw new DomainException("Usuario nao existe");
            }

            return LerDto(usuario); // se houver um usuario, converte para DTO e devolve para o usuario
        }

        public LerUsuarioDto ObterPorEmail(string email)
        {
            Usuario? usuario = _repository.ObterPorEmail(email);

            if (usuario == null)
            {
                throw new DomainException("Usuario nao existe");
            }

            return LerDto(usuario);
        }
    }
}
